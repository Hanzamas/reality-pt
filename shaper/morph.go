package shaper

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

// tlsRecordOverhead is what TLS 1.3 adds to a record body: the inner content
// type and the authentication tag. A frame of F bytes is a record of F+17.
const tlsRecordOverhead = 17

// realOpenings holds the start of real HTTP/2 connections: sizes and
// directions of the first application data records after the handshake,
// collected by the traces workflow. It holds no content and no addresses.
//
//go:embed data/real-openings.json
var realOpenings []byte

// Opening is the start of one real connection as a network observer sees it.
type Opening struct {
	Steps []OpeningStep
}

// OpeningStep is one record of an opening.
type OpeningStep struct {
	// Up is true for a record sent by the client.
	Up bool
	// Len is the length of the record body.
	Len int
}

// ParseOpenings reads openings from the JSON written by the traces workflow.
func ParseOpenings(data []byte) ([]Opening, error) {
	var file struct {
		Traces []struct {
			Steps [][2]int `json:"steps"`
		} `json:"traces"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse openings: %w", err)
	}
	openings := make([]Opening, 0, len(file.Traces))
	for _, t := range file.Traces {
		var o Opening
		for _, s := range t.Steps {
			o.Steps = append(o.Steps, OpeningStep{Up: s[0] == 1, Len: s[1]})
		}
		if len(o.Steps) > 0 {
			openings = append(openings, o)
		}
	}
	if len(openings) == 0 {
		return nil, fmt.Errorf("parse openings: no traces")
	}
	return openings, nil
}

// MorphConfig controls how Morph follows a real opening.
type MorphConfig struct {
	// Openings are the real connections to follow. Each tunnel follows one,
	// chosen at random.
	Openings []Opening
	// MaxSlots is how many of its own records each side shapes.
	MaxSlots int
	// Idle is how long a side waits without real data before it sends a decoy
	// to keep to the opening.
	Idle time.Duration
	// Later pads the frames after the opening.
	Later PaddingConfig
}

// DefaultMorphIdle is the pause before a decoy.
const DefaultMorphIdle = 25 * time.Millisecond

// Morph makes the start of the tunnel follow the start of a real connection.
// Each side picks a real opening and takes the records its own direction sends.
// Real data fills those records, split or padded to the size the opening has
// there, and a decoy takes the place of data that does not come. After the
// opening, frames get light random padding.
//
// This is an attempt to make the opening exchange look like ordinary HTTPS
// instead of like TLS inside TLS. How well it works is measured in
// internal/measure, against traffic the profiles were not taken from.
type Morph struct {
	cfg MorphConfig
}

// NewMorph returns a Morph shaper.
func NewMorph(cfg MorphConfig) *Morph { return &Morph{cfg: cfg} }

// DefaultMorph returns a Morph that follows the real openings shipped with the
// package.
func DefaultMorph() (*Morph, error) {
	openings, err := ParseOpenings(realOpenings)
	if err != nil {
		return nil, err
	}
	later := DefaultPadding
	return NewMorph(MorphConfig{Openings: openings, MaxSlots: 12, Idle: DefaultMorphIdle, Later: later}), nil
}

// Wrap implements Shaper. The client follows the records of its opening that
// the client sent, and the server the records the server sent.
func (m *Morph) Wrap(c net.Conn, role Role) net.Conn {
	mc := &morphConn{Conn: c, cfg: m.cfg, done: make(chan struct{}), last: time.Now()}
	mc.slots = m.pickSlots(role)
	if len(mc.slots) > 0 && m.cfg.Idle > 0 {
		go mc.decoyLoop()
	}
	return mc
}

// pickSlots chooses an opening and returns the frame sizes for one side.
func (m *Morph) pickSlots(role Role) []int {
	if len(m.cfg.Openings) == 0 {
		return nil
	}
	opening := m.cfg.Openings[rand.IntN(len(m.cfg.Openings))]
	var slots []int
	for _, step := range opening.Steps {
		if step.Up != (role == Client) {
			continue
		}
		slots = append(slots, max(step.Len-tlsRecordOverhead, frameHeaderLen+1))
		if len(slots) == m.cfg.MaxSlots {
			break
		}
	}
	return slots
}

type morphConn struct {
	net.Conn
	cfg MorphConfig
	frameReader

	wmu   sync.Mutex
	slots []int     // frame sizes still to be sent, in order
	last  time.Time // when a frame was last written

	done chan struct{}
	once sync.Once
}

// Read implements net.Conn. It returns payload bytes only.
func (c *morphConn) Read(p []byte) (int, error) { return c.read(c.Conn, p) }

// Write implements net.Conn.
func (c *morphConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	written := 0
	for len(p) > 0 {
		var n, pad int
		if len(c.slots) > 0 {
			size := c.slots[0]
			c.slots = c.slots[1:]
			n = min(len(p), size-frameHeaderLen, maxPayload)
			pad = size - frameHeaderLen - n
		} else {
			n = min(len(p), maxPayload)
			pad = laterPad(c.cfg.Later)
		}
		if err := writeFrame(c.Conn, p[:n], pad); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
		c.last = time.Now()
	}
	return written, nil
}

// decoyLoop fills a slot with padding whenever the side has been quiet for
// Idle, until the opening is used up or the connection closes.
func (c *morphConn) decoyLoop() {
	ticker := time.NewTicker(c.cfg.Idle)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
		}
		c.wmu.Lock()
		if len(c.slots) == 0 {
			c.wmu.Unlock()
			return
		}
		if time.Since(c.last) >= c.cfg.Idle {
			size := c.slots[0]
			c.slots = c.slots[1:]
			_ = writeFrame(c.Conn, nil, size-frameHeaderLen)
			c.last = time.Now()
		}
		c.wmu.Unlock()
	}
}

// Close implements net.Conn.
func (c *morphConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

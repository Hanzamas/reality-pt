package shaper

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"time"
)

const (
	// tlsRecordOverhead is what TLS 1.3 adds to a record body: the inner
	// content type and the authentication tag. A frame of F bytes is a record
	// of F+17.
	tlsRecordOverhead = 17
	// morphPrefixLen is the room the client's first frame spends on naming the
	// opening: a 2-byte index and a 2-byte count of openings.
	morphPrefixLen = 4
	// minFrame is the smallest frame a step can have: the header, the prefix
	// the first one carries, and a byte of data.
	minFrame = frameHeaderLen + morphPrefixLen + 1
	// maxBuffered bounds the data held for a reader that is slow.
	maxBuffered = 1 << 20

	// DefaultMorphIdle is how long a side waits at its turn before it sends a
	// decoy instead of data.
	DefaultMorphIdle = 15 * time.Millisecond
	// DefaultMorphSteps is how many records of an opening are followed.
	DefaultMorphSteps = 16
)

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
		return nil, errors.New("parse openings: no traces")
	}
	return openings, nil
}

// MorphConfig controls how Morph follows a real opening.
type MorphConfig struct {
	// Openings are the real connections to follow. The client picks one at
	// random for each tunnel and tells the server which. Both ends must be
	// built with the same list.
	Openings []Opening
	// MaxSteps is how many records of the opening, from both ends together,
	// are followed. Zero means DefaultMorphSteps.
	MaxSteps int
	// Idle is how long a side waits at its turn without data before it sends a
	// decoy. Zero means DefaultMorphIdle.
	Idle time.Duration
	// Later pads the frames after the opening.
	Later PaddingConfig
}

// Morph makes the start of the tunnel follow the start of a real connection,
// record by record and in the same order. The client picks a real opening and
// tells the server which. After that the two ends take turns, each sending its
// next record of the opening when it is its turn: real data, padded or split to
// the size the opening has there, or a decoy if no data comes. A turn lasts
// until the other end's record arrives, so the sequence of directions on the
// wire is that of the real connection. After the opening, frames get light
// random padding.
//
// The price is delay: the data inside the tunnel waits for its turn, up to Idle
// per step, during the first steps of a connection.
//
// How well this works is measured in internal/measure, against traffic the
// openings were not taken from.
type Morph struct {
	cfg    MorphConfig
	usable []Opening
}

// NewMorph returns a Morph shaper. Openings that do not start with a client
// record are not used.
func NewMorph(cfg MorphConfig) *Morph {
	if cfg.MaxSteps <= 0 {
		cfg.MaxSteps = DefaultMorphSteps
	}
	if cfg.Idle <= 0 {
		cfg.Idle = DefaultMorphIdle
	}
	m := &Morph{cfg: cfg}
	for _, o := range cfg.Openings {
		if len(o.Steps) >= 2 && o.Steps[0].Up {
			m.usable = append(m.usable, o)
		}
	}
	return m
}

// DefaultMorph returns a Morph that follows the real openings shipped with the
// package.
func DefaultMorph() (*Morph, error) {
	openings, err := ParseOpenings(realOpenings)
	if err != nil {
		return nil, err
	}
	return NewMorph(MorphConfig{Openings: openings, Later: DefaultPadding}), nil
}

// Wrap implements Shaper.
func (m *Morph) Wrap(c net.Conn, role Role) net.Conn {
	if len(m.usable) == 0 {
		return NewPadding(m.cfg.Later).Wrap(c, role)
	}
	mc := &morphConn{Conn: c, m: m, role: role, done: make(chan struct{})}
	mc.cond = sync.NewCond(&mc.mu)
	if role == Client {
		mc.mu.Lock()
		mc.setPlanLocked(rand.IntN(len(m.usable)))
		mc.mu.Unlock()
	}
	go mc.readLoop()
	go mc.decoyLoop()
	return mc
}

var (
	errMorphPrefix = errors.New("shaper: the first frame does not name an opening")
	errMorphTable  = errors.New("shaper: the peer uses a different list of openings")
)

// planStep is one record of the opening that is being followed.
type planStep struct {
	mine bool // this end sends it
	size int  // frame size in bytes
}

type morphConn struct {
	net.Conn
	m    *Morph
	role Role

	wmu sync.Mutex // one writer at a time

	mu        sync.Mutex // guards what follows
	cond      *sync.Cond
	index     int
	plan      []planStep
	ready     bool      // the plan is known
	pos       int       // the step that is next
	turnAt    time.Time // when the current step became next
	rbuf      bytes.Buffer
	rerr      error // why reading stopped
	closed    bool
	rdeadline time.Time

	done chan struct{}
	once sync.Once
}

// setPlanLocked chooses the opening and builds this end's plan from it.
func (c *morphConn) setPlanLocked(index int) {
	c.index = index
	steps := c.m.usable[index].Steps
	c.plan = c.plan[:0]
	for _, s := range steps[:min(len(steps), c.m.cfg.MaxSteps)] {
		c.plan = append(c.plan, planStep{
			mine: s.Up == (c.role == Client),
			size: max(s.Len-tlsRecordOverhead, minFrame),
		})
	}
	c.ready = true
	c.turnAt = time.Now()
	c.cond.Broadcast()
}

func (c *morphConn) advanceLocked() {
	c.pos++
	c.turnAt = time.Now()
	c.cond.Broadcast()
}

// myTurnLocked reports whether the next step is this end's.
func (c *morphConn) myTurnLocked() bool {
	return c.ready && c.pos < len(c.plan) && c.plan[c.pos].mine
}

// readLoop reads frames in the background so that the peer's steps are counted
// even while the application is busy writing.
func (c *morphConn) readLoop() {
	first := true
	for {
		var header [frameHeaderLen]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			c.fail(err)
			return
		}
		payload := make([]byte, binary.BigEndian.Uint16(header[0:2]))
		if _, err := io.ReadFull(c.Conn, payload); err != nil {
			c.fail(unexpectedEOF(err))
			return
		}
		if pad := int64(binary.BigEndian.Uint16(header[2:4])); pad > 0 {
			if _, err := io.CopyN(io.Discard, c.Conn, pad); err != nil {
				c.fail(unexpectedEOF(err))
				return
			}
		}

		c.mu.Lock()
		if first && c.role == Server {
			// The client's first frame names the opening.
			if len(payload) < morphPrefixLen {
				c.mu.Unlock()
				c.fail(errMorphPrefix)
				return
			}
			index := int(binary.BigEndian.Uint16(payload[0:2]))
			count := int(binary.BigEndian.Uint16(payload[2:4]))
			if count != len(c.m.usable) || index >= count {
				c.mu.Unlock()
				c.fail(errMorphTable)
				return
			}
			payload = payload[morphPrefixLen:]
			c.setPlanLocked(index)
		}
		first = false

		// A frame from the peer completes the peer's step.
		if c.ready && c.pos < len(c.plan) && !c.plan[c.pos].mine {
			c.advanceLocked()
		}
		c.rbuf.Write(payload)
		c.cond.Broadcast()
		for c.rbuf.Len() > maxBuffered && !c.closed {
			c.cond.Wait()
		}
		c.mu.Unlock()
	}
}

// fail records why reading stopped and wakes everyone who waits.
func (c *morphConn) fail(err error) {
	c.mu.Lock()
	if c.rerr == nil {
		c.rerr = err
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	if errors.Is(err, errMorphPrefix) || errors.Is(err, errMorphTable) {
		_ = c.Conn.Close()
	}
}

// Read implements net.Conn. It returns payload bytes only.
func (c *morphConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.rbuf.Len() == 0 {
		if c.rerr != nil {
			return 0, c.rerr
		}
		if c.closed {
			return 0, net.ErrClosed
		}
		if d := c.rdeadline; !d.IsZero() {
			if !time.Now().Before(d) {
				return 0, os.ErrDeadlineExceeded
			}
			wake := time.AfterFunc(time.Until(d), func() {
				c.mu.Lock()
				c.cond.Broadcast()
				c.mu.Unlock()
			})
			c.cond.Wait()
			wake.Stop()
			continue
		}
		c.cond.Wait()
	}
	n, _ := c.rbuf.Read(p)
	c.cond.Broadcast() // room for the read loop
	return n, nil
}

// Write implements net.Conn. Each chunk of p goes out as one frame at this
// end's next turn.
func (c *morphConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	written := 0
	for len(p) > 0 {
		step, planned, first, err := c.takeTurn()
		if err != nil {
			return written, err
		}
		var prefix []byte
		room := min(len(p), maxPayload)
		pad := 0
		if planned {
			room = step.size - frameHeaderLen
			if first {
				prefix = c.prefix()
				room -= len(prefix)
			}
			room = min(len(p), room, maxPayload)
			pad = step.size - frameHeaderLen - len(prefix) - room
		} else {
			pad = laterPad(c.m.cfg.Later)
		}
		if err := writeFrame(c.Conn, append(prefix, p[:room]...), pad); err != nil {
			return written, err
		}
		written += room
		p = p[room:]
	}
	return written, nil
}

// takeTurn waits for this end's turn and takes it. planned is false once the
// opening is over. first is true for the client's very first frame, which
// names the opening.
func (c *morphConn) takeTurn() (step planStep, planned, first bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		switch {
		case c.closed:
			return step, false, false, net.ErrClosed
		case c.rerr != nil:
			return step, false, false, io.ErrClosedPipe
		case c.ready && c.pos >= len(c.plan):
			return step, false, false, nil
		case c.myTurnLocked():
			step, first = c.plan[c.pos], c.role == Client && c.pos == 0
			c.advanceLocked()
			return step, true, first, nil
		}
		c.cond.Wait()
	}
}

// prefix names the opening for the server.
func (c *morphConn) prefix() []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(c.index))
	return binary.BigEndian.AppendUint16(b, uint16(len(c.m.usable)))
}

// decoyLoop sends a decoy when this end's turn has passed without data for
// Idle. It stops when the opening is over or the connection closes.
func (c *morphConn) decoyLoop() {
	ticker := time.NewTicker(c.m.cfg.Idle)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
		}

		c.wmu.Lock()
		c.mu.Lock()
		finished := c.closed || c.rerr != nil || (c.ready && c.pos >= len(c.plan))
		var (
			step  planStep
			first bool
			send  bool
		)
		if !finished && c.myTurnLocked() && time.Since(c.turnAt) >= c.m.cfg.Idle {
			step, first, send = c.plan[c.pos], c.role == Client && c.pos == 0, true
			c.advanceLocked()
		}
		c.mu.Unlock()
		if send {
			var prefix []byte
			if first {
				prefix = c.prefix()
			}
			_ = writeFrame(c.Conn, prefix, step.size-frameHeaderLen-len(prefix))
		}
		c.wmu.Unlock()
		if finished {
			return
		}
	}
}

// SetDeadline implements net.Conn. The read deadline is kept here, because the
// background reader must never time out on the underlying connection.
func (c *morphConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

// SetReadDeadline implements net.Conn.
func (c *morphConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdeadline = t
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

// Close implements net.Conn.
func (c *morphConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.mu.Lock()
		c.closed = true
		c.cond.Broadcast()
		c.mu.Unlock()
	})
	return c.Conn.Close()
}

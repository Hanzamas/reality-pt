package shaper

import (
	"math/rand/v2"
	"net"
	"sync"
)

// PaddingConfig controls how Padding sizes the frames it writes.
type PaddingConfig struct {
	// FirstFrames is how many frames at the start of a connection get a size
	// drawn from FirstMin to FirstMax. The start of a connection is where the
	// handshake of the protocol inside the tunnel shows its shape.
	FirstFrames int
	// FirstMin and FirstMax bound the size of those frames, header included.
	// A payload larger than the drawn size is sent as it is.
	FirstMin, FirstMax int
	// PadChance is the probability that a later frame gets padding.
	PadChance float64
	// MaxPad is the largest padding added to a later frame.
	MaxPad int
	// MaxDecoys is the most decoy frames each side sends as soon as the
	// tunnel opens, before any real data. A decoy carries no payload, only
	// padding. Real servers and clients also speak first after a handshake,
	// with settings and session tickets.
	MaxDecoys int
	// DecoyMin and DecoyMax bound the size of a decoy frame, header included.
	DecoyMin, DecoyMax int
}

// DefaultPadding is the policy behind the shaper named "padding".
var DefaultPadding = PaddingConfig{
	FirstFrames: 12,
	FirstMin:    200,
	FirstMax:    1400,
	PadChance:   0.5,
	MaxPad:      300,
	MaxDecoys:   3,
	DecoyMin:    40,
	DecoyMax:    300,
}

// Padding frames every write and adds random padding to it, so the record
// sizes on the wire no longer follow the sizes of the traffic inside. It hides
// runs of equal-size records. It does not change who speaks when, so it does
// not hide the opening exchange of the protocol inside the tunnel.
type Padding struct {
	cfg PaddingConfig
}

// NewPadding returns a Padding shaper with the given policy.
func NewPadding(cfg PaddingConfig) *Padding { return &Padding{cfg: cfg} }

// Wrap implements Shaper. Both roles behave the same.
func (p *Padding) Wrap(c net.Conn, _ Role) net.Conn {
	pc := &paddingConn{Conn: c, cfg: p.cfg}
	pc.sendDecoys()
	return pc
}

type paddingConn struct {
	net.Conn
	cfg PaddingConfig
	frameReader

	wmu   sync.Mutex
	early int // frames written so far, up to cfg.FirstFrames
}

// Read implements net.Conn. It returns payload bytes only.
func (c *paddingConn) Read(p []byte) (int, error) { return c.read(c.Conn, p) }

// Write implements net.Conn. Each chunk of p becomes one frame and one write
// to the underlying connection.
func (c *paddingConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	written := 0
	for len(p) > 0 {
		n := min(len(p), maxPayload)
		if err := writeFrame(c.Conn, p[:n], c.padFor(n)); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// sendDecoys starts writing the opening decoy frames in the background. It
// holds the write lock until they are out, so no real data can overtake them,
// and it does not block the caller. A write failure is ignored: the next real
// write meets the same error.
func (c *paddingConn) sendDecoys() {
	cfg := c.cfg
	if cfg.MaxDecoys <= 0 || cfg.DecoyMax < cfg.DecoyMin {
		return
	}
	count := rand.IntN(cfg.MaxDecoys + 1)
	if count == 0 {
		return
	}
	c.wmu.Lock()
	go func() {
		defer c.wmu.Unlock()
		for ; count > 0; count-- {
			size := cfg.DecoyMin + rand.IntN(cfg.DecoyMax-cfg.DecoyMin+1)
			if err := writeFrame(c.Conn, nil, max(0, size-frameHeaderLen)); err != nil {
				return
			}
			c.early++
		}
	}()
}

// padFor returns the padding for a frame that carries n payload bytes.
func (c *paddingConn) padFor(n int) int {
	cfg := c.cfg
	if c.early < cfg.FirstFrames {
		c.early++
		target := cfg.FirstMin
		if cfg.FirstMax > cfg.FirstMin {
			target += rand.IntN(cfg.FirstMax - cfg.FirstMin + 1)
		}
		return max(0, target-frameHeaderLen-n)
	}
	return laterPad(cfg)
}

// laterPad returns the random padding for a frame after the opening.
func laterPad(cfg PaddingConfig) int {
	if cfg.MaxPad > 0 && rand.Float64() < cfg.PadChance {
		return 1 + rand.IntN(cfg.MaxPad)
	}
	return 0
}

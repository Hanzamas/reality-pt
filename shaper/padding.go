package shaper

import (
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"sync"
)

const (
	frameHeaderLen = 4
	// maxPayload keeps a frame, with the largest padding, inside one TLS
	// record of at most 16 KiB so that one frame is one record on the wire.
	maxPayload = 15000
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
}

// DefaultPadding is the policy behind the shaper named "padding".
var DefaultPadding = PaddingConfig{
	FirstFrames: 12,
	FirstMin:    200,
	FirstMax:    1400,
	PadChance:   0.5,
	MaxPad:      300,
}

// Padding frames every write and adds random padding to it, so the record
// sizes on the wire no longer follow the sizes of the traffic inside. A frame
// is a 2-byte payload length, a 2-byte padding length, the payload, then the
// padding. The padding is zeros: the tunnel encrypts it.
type Padding struct {
	cfg PaddingConfig
}

// NewPadding returns a Padding shaper with the given policy.
func NewPadding(cfg PaddingConfig) *Padding { return &Padding{cfg: cfg} }

// Wrap implements Shaper.
func (p *Padding) Wrap(c net.Conn) net.Conn { return &paddingConn{Conn: c, cfg: p.cfg} }

var framePool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, frameHeaderLen+maxPayload+2048)
		return &b
	},
}

type paddingConn struct {
	net.Conn
	cfg PaddingConfig

	wmu   sync.Mutex
	early int // frames written so far, up to cfg.FirstFrames

	rmu       sync.Mutex
	remaining int // payload bytes of the current frame not yet returned
	discard   int // padding bytes of the current frame not yet skipped
}

// Write implements net.Conn. Each chunk of p becomes one frame and one write
// to the underlying connection.
func (c *paddingConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	written := 0
	for len(p) > 0 {
		n := min(len(p), maxPayload)
		pad := c.padFor(n)

		bufp := framePool.Get().(*[]byte)
		frame := (*bufp)[:0]
		frame = binary.BigEndian.AppendUint16(frame, uint16(n))
		frame = binary.BigEndian.AppendUint16(frame, uint16(pad))
		frame = append(frame, p[:n]...)
		frame = append(frame, make([]byte, pad)...)

		_, err := c.Conn.Write(frame)
		*bufp = frame
		framePool.Put(bufp)
		if err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
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
	if cfg.MaxPad > 0 && rand.Float64() < cfg.PadChance {
		return 1 + rand.IntN(cfg.MaxPad)
	}
	return 0
}

// Read implements net.Conn. It returns payload bytes only.
func (c *paddingConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}
	for c.remaining == 0 {
		if c.discard > 0 {
			if _, err := io.CopyN(io.Discard, c.Conn, int64(c.discard)); err != nil {
				return 0, unexpectedEOF(err)
			}
			c.discard = 0
		}
		var header [frameHeaderLen]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		c.remaining = int(binary.BigEndian.Uint16(header[0:2]))
		c.discard = int(binary.BigEndian.Uint16(header[2:4]))
	}
	n, err := c.Conn.Read(p[:min(len(p), c.remaining)])
	c.remaining -= n
	if c.remaining > 0 && err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

// unexpectedEOF reports a connection that ended inside a frame.
func unexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

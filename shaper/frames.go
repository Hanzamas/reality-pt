package shaper

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
)

const (
	// frameHeaderLen is a 2-byte payload length and a 2-byte padding length.
	frameHeaderLen = 4
	// maxPayload keeps a frame, with the largest padding, inside one TLS
	// record of at most 16 KiB so that one frame is one record on the wire.
	maxPayload = 15000
)

var framePool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, frameHeaderLen+maxPayload+2048)
		return &b
	},
}

// writeFrame writes one frame to c in a single write: the lengths, the
// payload, then pad zero bytes. The padding is zeros because the tunnel
// encrypts it.
func writeFrame(c net.Conn, payload []byte, pad int) error {
	bufp := framePool.Get().(*[]byte)
	frame := (*bufp)[:0]
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	frame = binary.BigEndian.AppendUint16(frame, uint16(pad))
	frame = append(frame, payload...)
	frame = append(frame, make([]byte, pad)...)

	_, err := c.Write(frame)
	*bufp = frame
	framePool.Put(bufp)
	return err
}

// frameReader returns the payload of the frames that arrive on a connection
// and skips the padding.
type frameReader struct {
	mu        sync.Mutex
	remaining int // payload bytes of the current frame not yet returned
	discard   int // padding bytes of the current frame not yet skipped
}

func (r *frameReader) read(c net.Conn, p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}
	for r.remaining == 0 {
		if r.discard > 0 {
			if _, err := io.CopyN(io.Discard, c, int64(r.discard)); err != nil {
				return 0, unexpectedEOF(err)
			}
			r.discard = 0
		}
		var header [frameHeaderLen]byte
		if _, err := io.ReadFull(c, header[:]); err != nil {
			return 0, err
		}
		r.remaining = int(binary.BigEndian.Uint16(header[0:2]))
		r.discard = int(binary.BigEndian.Uint16(header[2:4]))
	}
	n, err := c.Read(p[:min(len(p), r.remaining)])
	r.remaining -= n
	if r.remaining > 0 && err == io.EOF {
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

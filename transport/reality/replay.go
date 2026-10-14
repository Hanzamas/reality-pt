package reality

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Offsets inside the first TLS record when it carries a ClientHello.
const (
	recordHeaderLen      = 5
	recordTypeHandshake  = 0x16
	handshakeClientHello = 0x01

	helloTypeOffset      = recordHeaderLen          // handshake message type
	helloRandomOffset    = recordHeaderLen + 4 + 2  // after handshake header and legacy version
	helloSessionIDLenOff = helloRandomOffset + 32   // session ID length byte
	helloSessionIDOffset = helloSessionIDLenOff + 1 // first byte of the session ID

	// A ClientHello cannot be shorter than the fields up to its session ID,
	// and a record body is capped at 2^14 bytes.
	minHelloRecord = helloSessionIDOffset + sessionIDLen
	maxRecordBody  = 1 << 14
)

const (
	// replayCacheSize bounds the memory the replay cache can use.
	replayCacheSize = 1 << 17
	// replayTTLWithoutClock keeps entries for an hour when the server does not
	// check client clocks, so the cache cannot grow without bound.
	replayTTLWithoutClock = time.Hour
)

// parseHelloRecord reads the random of a ClientHello from the first TLS record
// of a connection. ok is false if rec is not a ClientHello with a 32-byte
// session ID, the only kind that can carry a token.
func parseHelloRecord(rec []byte) (random [32]byte, ok bool) {
	if len(rec) < minHelloRecord ||
		rec[0] != recordTypeHandshake ||
		rec[helloTypeOffset] != handshakeClientHello ||
		rec[helloSessionIDLenOff] != sessionIDLen {
		return random, false
	}
	copy(random[:], rec[helloRandomOffset:helloRandomOffset+len(random)])
	return random, true
}

// seenCache remembers recent ClientHello randoms. It evicts the oldest entry
// when it is full, so a flood of hellos can push old ones out. That costs the
// attacker one connection to the cover site per entry.
type seenCache struct {
	mu    sync.Mutex
	ttl   time.Duration
	max   int
	now   func() time.Time
	seen  map[[32]byte]struct{}
	queue []seenEntry // oldest first
	head  int         // index of the oldest live entry in queue
}

type seenEntry struct {
	key [32]byte
	at  time.Time
}

func newSeenCache(ttl time.Duration, max int, now func() time.Time) *seenCache {
	return &seenCache{ttl: ttl, max: max, now: now, seen: make(map[[32]byte]struct{})}
}

// newReplayCache sizes a cache for a server that accepts tokens up to
// maxTimeDiff old or new. A token stays replayable for twice that span.
func newReplayCache(maxTimeDiff time.Duration) *seenCache {
	ttl := 2 * maxTimeDiff
	if maxTimeDiff <= 0 {
		ttl = replayTTLWithoutClock
	}
	return newSeenCache(ttl, replayCacheSize, time.Now)
}

// firstSeen records key and reports whether it is new.
func (c *seenCache) firstSeen(key [32]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	for c.live() > 0 && now.Sub(c.queue[c.head].at) >= c.ttl {
		c.pop()
	}
	if _, dup := c.seen[key]; dup {
		return false
	}
	for c.live() >= c.max {
		c.pop()
	}
	c.seen[key] = struct{}{}
	c.queue = append(c.queue, seenEntry{key: key, at: now})
	return true
}

func (c *seenCache) live() int { return len(c.queue) - c.head }

func (c *seenCache) pop() {
	delete(c.seen, c.queue[c.head].key)
	c.head++
	if c.head > 1024 && c.head*2 > len(c.queue) {
		c.queue = append(c.queue[:0], c.queue[c.head:]...)
		c.head = 0
	}
}

// replayListener wraps TCP connections so that a ClientHello seen before loses
// its token. The REALITY server then fails to authenticate it and forwards it
// to the cover site, as it does for any stranger.
type replayListener struct {
	net.Listener
	cache *seenCache
}

func (l *replayListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return c, nil
	}
	return &replayConn{conn: tcp, cache: l.cache}, nil
}

// replayConn delivers the first TLS record of a connection from a buffer and
// everything after it straight from the socket. It deliberately does not embed
// *net.TCPConn: the promoted WriteTo would let io.Copy read around the buffer.
//
// Only one goroutine may call Read.
type replayConn struct {
	conn    *net.TCPConn
	cache   *seenCache
	once    sync.Once
	pending []byte
	err     error
}

func (c *replayConn) Read(p []byte) (int, error) {
	c.once.Do(c.peek)
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.err != nil {
		return 0, c.err
	}
	return c.conn.Read(p)
}

// peek reads the first TLS record. Whatever arrives is passed on unchanged,
// except that a replayed ClientHello has one session ID byte flipped.
func (c *replayConn) peek() {
	var header [recordHeaderLen]byte
	n, err := io.ReadFull(c.conn, header[:])
	c.pending = append(c.pending, header[:n]...)
	if err != nil {
		c.err = streamEnd(err)
		return
	}
	length := int(header[3])<<8 | int(header[4])
	if header[0] != recordTypeHandshake || length < minHelloRecord-recordHeaderLen || length > maxRecordBody {
		return
	}

	body := make([]byte, length)
	n, err = io.ReadFull(c.conn, body)
	c.pending = append(c.pending, body[:n]...)
	if err != nil {
		c.err = streamEnd(err)
		return
	}
	if random, ok := parseHelloRecord(c.pending); ok && !c.cache.firstSeen(random) {
		c.pending[helloSessionIDOffset] ^= 0xff
	}
}

// streamEnd maps a short read to io.EOF, which is what the next Read of a
// closed connection returns.
func streamEnd(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return io.EOF
	}
	return err
}

func (c *replayConn) Write(p []byte) (int, error)        { return c.conn.Write(p) }
func (c *replayConn) Close() error                       { return c.conn.Close() }
func (c *replayConn) CloseWrite() error                  { return c.conn.CloseWrite() }
func (c *replayConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *replayConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *replayConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *replayConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *replayConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

package reality

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// fakeHello builds a TLS record holding a ClientHello-shaped message with a
// 32-byte session ID. Only the fields the replay guard reads are meaningful.
func fakeHello(random byte) []byte {
	body := make([]byte, 4+2+32+1+sessionIDLen+8)
	body[0] = handshakeClientHello
	n := len(body) - 4
	body[1], body[2], body[3] = byte(n>>16), byte(n>>8), byte(n)
	body[4], body[5] = 3, 3
	for i := 6; i < 6+32; i++ {
		body[i] = random
	}
	body[38] = sessionIDLen
	for i := 39; i < 39+sessionIDLen; i++ {
		body[i] = 0xaa
	}
	rec := []byte{recordTypeHandshake, 3, 1, byte(len(body) >> 8), byte(len(body))}
	return append(rec, body...)
}

func TestParseHelloRecord(t *testing.T) {
	rec := fakeHello(7)
	random, ok := parseHelloRecord(rec)
	if !ok {
		t.Fatal("a ClientHello record was not recognized")
	}
	if random != [32]byte(bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("random = %x", random)
	}
	if rec[helloSessionIDOffset] != 0xaa {
		t.Fatal("session ID offset does not point at the session ID")
	}

	for name, bad := range map[string][]byte{
		"empty":            nil,
		"short":            rec[:40],
		"application data": append([]byte{0x17}, rec[1:]...),
		"server hello":     append(append([]byte{}, rec[:recordHeaderLen]...), append([]byte{0x02}, rec[recordHeaderLen+1:]...)...),
	} {
		if _, ok := parseHelloRecord(bad); ok {
			t.Errorf("%s was taken for a ClientHello", name)
		}
	}

	noSessionID := fakeHello(7)
	noSessionID[helloSessionIDLenOff] = 0
	if _, ok := parseHelloRecord(noSessionID); ok {
		t.Error("a ClientHello without a 32-byte session ID was accepted")
	}
}

func FuzzParseHelloRecord(f *testing.F) {
	f.Add(fakeHello(1))
	f.Add([]byte{})
	f.Add([]byte{0x16, 3, 1, 0, 0})
	f.Fuzz(func(t *testing.T, rec []byte) {
		random, ok := parseHelloRecord(rec)
		if ok && !bytes.Equal(random[:], rec[helloRandomOffset:helloRandomOffset+32]) {
			t.Fatalf("random does not match the record bytes")
		}
	})
}

func TestSeenCache(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newSeenCache(time.Minute, 3, func() time.Time { return now })
	key := func(b byte) [32]byte { return [32]byte(bytes.Repeat([]byte{b}, 32)) }

	if !c.firstSeen(key(1)) {
		t.Fatal("a new key was reported as seen")
	}
	if c.firstSeen(key(1)) {
		t.Fatal("a repeated key was reported as new")
	}

	now = now.Add(time.Minute)
	if !c.firstSeen(key(1)) {
		t.Fatal("a key older than the TTL was still remembered")
	}

	// Capacity: with room for 3, adding a fourth evicts the oldest.
	c.firstSeen(key(2))
	c.firstSeen(key(3))
	c.firstSeen(key(4))
	if !c.firstSeen(key(1)) {
		t.Fatal("the oldest key survived eviction")
	}
	if c.firstSeen(key(4)) {
		t.Fatal("a recent key was evicted too early")
	}
}

func TestSeenCacheStaysBounded(t *testing.T) {
	c := newSeenCache(time.Hour, 100, time.Now)
	for i := 0; i < 10_000; i++ {
		var k [32]byte
		k[0], k[1] = byte(i), byte(i>>8)
		c.firstSeen(k)
	}
	if got := len(c.seen); got != 100 {
		t.Fatalf("cache holds %d entries, want 100", got)
	}
	if c.live() != 100 {
		t.Fatalf("queue holds %d live entries, want 100", c.live())
	}
	if len(c.queue) > 100+2048 {
		t.Fatalf("queue slice grew to %d", len(c.queue))
	}
}

// guarded returns the server side of a loopback connection that already
// carries the given client bytes, wrapped by the replay guard.
func guarded(t *testing.T, cache *seenCache, clientBytes []byte) net.Conn {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inner.Close() })
	ln := &replayListener{Listener: inner, cache: cache}

	go func() {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			return
		}
		_, _ = c.Write(clientBytes)
		_ = c.(*net.TCPConn).CloseWrite()
		time.Sleep(2 * time.Second)
		_ = c.Close()
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	return conn
}

func TestReplayedHelloLosesItsToken(t *testing.T) {
	cache := newSeenCache(time.Hour, 100, time.Now)
	hello := fakeHello(9)
	trailing := []byte("more bytes after the hello")
	wire := append(append([]byte{}, hello...), trailing...)

	first, err := io.ReadAll(guarded(t, cache, wire))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, wire) {
		t.Fatal("the first ClientHello was changed")
	}

	second, err := io.ReadAll(guarded(t, cache, wire))
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != len(wire) {
		t.Fatalf("replayed stream has %d bytes, want %d", len(second), len(wire))
	}
	want := append([]byte{}, wire...)
	want[helloSessionIDOffset] ^= 0xff
	if !bytes.Equal(second, want) {
		t.Fatal("a replayed ClientHello must differ from the original in exactly the first session ID byte")
	}
}

func TestOtherTrafficPassesThroughUnchanged(t *testing.T) {
	cases := map[string][]byte{
		"HTTP request": []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
		"garbage":      bytes.Repeat([]byte{0xa5}, 200),
		"short":        {0x16, 0x03},
		"tiny record":  {0x16, 3, 1, 0, 2, 0xde, 0xad},
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			cache := newSeenCache(time.Hour, 100, time.Now)
			got, err := io.ReadAll(guarded(t, cache, wire))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, wire) {
				t.Fatalf("stream changed: got %x, want %x", got, wire)
			}
		})
	}
}

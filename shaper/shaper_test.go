package shaper

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestNoopReturnsSameConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	var s Shaper = Noop{}
	if got := s.Wrap(a, Client); got != a {
		t.Fatalf("Noop.Wrap returned a different conn: got %v, want %v", got, a)
	}
}

func TestByName(t *testing.T) {
	for _, name := range []string{"", "none", "padding", "PADDING"} {
		if _, err := ByName(name); err != nil {
			t.Errorf("ByName(%q): %v", name, err)
		}
	}
	if _, err := ByName("rot13"); err == nil {
		t.Error("an unknown shaper was accepted")
	}
	if got := Names(); len(got) != 3 || got[0] != "morph" || got[1] != "none" || got[2] != "padding" {
		t.Errorf("Names() = %v", got)
	}
}

// wirePair returns two shaped ends of a pipe plus a counter of the raw writes
// the first end made, which are the frames a censor would see as records.
func wirePair(t *testing.T, s Shaper) (shaped, peer net.Conn, frames *[]int) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	var mu sync.Mutex
	sizes := []int{}
	tapped := &tapConn{Conn: a, onWrite: func(n int) {
		mu.Lock()
		sizes = append(sizes, n)
		mu.Unlock()
	}}
	return s.Wrap(tapped, Client), s.Wrap(b, Client), &sizes
}

type tapConn struct {
	net.Conn
	onWrite func(int)
}

func (c *tapConn) Write(p []byte) (int, error) {
	c.onWrite(len(p))
	return c.Conn.Write(p)
}

func TestPaddingRoundTrip(t *testing.T) {
	left, right, _ := wirePair(t, NewPadding(DefaultPadding))

	// Sizes around the frame limit, plus tiny and empty writes.
	var payloads [][]byte
	for _, n := range []int{1, 2, 100, 514, 1400, 14999, 15000, 15001, 40000} {
		p := make([]byte, n)
		_, _ = rand.Read(p)
		payloads = append(payloads, p)
	}
	want := bytes.Join(payloads, nil)

	go func() {
		for _, p := range payloads {
			if _, err := left.Write(p); err != nil {
				return
			}
		}
		_, _ = left.Write(nil)
		_ = left.Close()
	}()

	_ = right.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(right)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round trip changed the data: got %d bytes, want %d", len(got), len(want))
	}
}

func TestPaddingReadsInSmallPieces(t *testing.T) {
	left, right, _ := wirePair(t, NewPadding(DefaultPadding))
	payload := bytes.Repeat([]byte("0123456789"), 300)
	go func() { _, _ = left.Write(payload); _ = left.Close() }()

	_ = right.SetReadDeadline(time.Now().Add(10 * time.Second))
	var got []byte
	buf := make([]byte, 7)
	for {
		n, err := right.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("read: %v", err)
			}
			break
		}
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %d bytes, want %d", len(got), len(payload))
	}
}

func TestPaddingConcurrentWritersKeepFramesWhole(t *testing.T) {
	left, right, _ := wirePair(t, NewPadding(DefaultPadding))

	const writers, perWriter = 8, 50
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := bytes.Repeat([]byte{byte('a' + w)}, 100)
			for i := 0; i < perWriter; i++ {
				if _, err := left.Write(msg); err != nil {
					return
				}
			}
		}()
	}
	go func() { wg.Wait(); _ = left.Close() }()

	_ = right.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(right)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != writers*perWriter*100 {
		t.Fatalf("got %d bytes, want %d", len(got), writers*perWriter*100)
	}
	// Each write is one frame, so every 100-byte message must be uniform.
	for i := 0; i < len(got); i += 100 {
		if len(bytes.Trim(got[i:i+100], string(got[i:i+1]))) != 0 {
			t.Fatalf("a message at offset %d was interleaved with another", i)
		}
	}
}

func TestPaddingSendsDecoysThatTheReaderSkips(t *testing.T) {
	cfg := PaddingConfig{MaxDecoys: 3, DecoyMin: 40, DecoyMax: 300}
	sawDecoys := false
	for attempt := 0; attempt < 60 && !sawDecoys; attempt++ {
		a, b := net.Pipe()
		var sizes []int
		var mu sync.Mutex
		tapped := &tapConn{Conn: a, onWrite: func(n int) { mu.Lock(); sizes = append(sizes, n); mu.Unlock() }}

		// The reading end needs no decoys of its own: nothing reads them here.
		reader := NewPadding(PaddingConfig{}).Wrap(b, Client)
		got := make(chan []byte, 1)
		go func() {
			_ = reader.SetReadDeadline(time.Now().Add(5 * time.Second))
			data, _ := io.ReadAll(reader)
			got <- data
		}()

		writer := NewPadding(cfg).Wrap(tapped, Client)
		// A real write waits for the decoys, so every frame but the last is a
		// decoy.
		if _, err := writer.Write([]byte("real")); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		if data := <-got; string(data) != "real" {
			t.Fatalf("the reader returned %q, want only the real data", data)
		}

		mu.Lock()
		decoys := append([]int(nil), sizes[:len(sizes)-1]...)
		mu.Unlock()
		for _, n := range decoys {
			sawDecoys = true
			if n < 40 || n > 300 {
				t.Errorf("a decoy frame is %d bytes, want 40 to 300", n)
			}
		}
		_ = b.Close()
	}
	if !sawDecoys {
		t.Fatal("no decoy frame in 60 connections")
	}
}

func TestPaddingSizesTheFirstFrames(t *testing.T) {
	cfg := PaddingConfig{FirstFrames: 6, FirstMin: 600, FirstMax: 900}
	left, right, sizes := wirePair(t, NewPadding(cfg))
	go func() { _, _ = io.Copy(io.Discard, right) }()

	for i := 0; i < 10; i++ {
		if _, err := left.Write(make([]byte, 50)); err != nil {
			t.Fatal(err)
		}
	}
	for i, n := range (*sizes)[:6] {
		if n < 600 || n > 900 {
			t.Errorf("early frame %d is %d bytes, want 600 to 900", i, n)
		}
	}
	for i, n := range (*sizes)[6:] {
		if n != frameHeaderLen+50 {
			t.Errorf("later frame %d is %d bytes without padding configured, want %d", i, n, frameHeaderLen+50)
		}
	}
}

func TestPaddingKeepsFramesInsideOneRecord(t *testing.T) {
	cfg := DefaultPadding
	left, right, sizes := wirePair(t, NewPadding(cfg))
	go func() { _, _ = io.Copy(io.Discard, right) }()

	if _, err := left.Write(make([]byte, 100_000)); err != nil {
		t.Fatal(err)
	}
	for i, n := range *sizes {
		if n > 16384 {
			t.Fatalf("frame %d is %d bytes, more than one TLS record holds", i, n)
		}
	}
}

func TestPaddingReadFailsOnATruncatedFrame(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	shaped := NewPadding(DefaultPadding).Wrap(b, Client)

	// A header that promises 10 payload bytes and 5 padding bytes, then EOF.
	go func() {
		_, _ = a.Write([]byte{0, 10, 0, 5, 1, 2, 3})
		_ = a.Close()
	}()
	_ = shaped.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := io.ReadAll(shaped)
	if err == nil {
		t.Fatal("a truncated frame was read without an error")
	}
}

func FuzzPaddingRead(f *testing.F) {
	f.Add([]byte{0, 3, 0, 2, 'a', 'b', 'c', 0, 0})
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 1})
	f.Fuzz(func(t *testing.T, wire []byte) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		go func() { _, _ = a.Write(wire); _ = a.Close() }()

		shaped := NewPadding(DefaultPadding).Wrap(b, Client)
		_ = shaped.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.Copy(io.Discard, shaped) // must not panic or hang
	})
}

func TestEmbeddedOpeningsParse(t *testing.T) {
	openings, err := ParseOpenings(realOpenings)
	if err != nil {
		t.Fatal(err)
	}
	if len(openings) < 50 {
		t.Fatalf("only %d openings are embedded", len(openings))
	}
	for i, o := range openings {
		for _, s := range o.Steps {
			if s.Len <= 0 || s.Len > 16384+256 {
				t.Fatalf("opening %d has a record of %d bytes", i, s.Len)
			}
		}
	}
	if _, err := ByName("morph"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseOpenings([]byte(`{"traces":[]}`)); err == nil {
		t.Error("an empty set of openings was accepted")
	}
	if _, err := ParseOpenings([]byte(`not json`)); err == nil {
		t.Error("bad JSON was accepted")
	}
}

// wireLog notes the frames written by either end of a pair, in order.
type wireLog struct {
	mu     sync.Mutex
	events []wireEvent
}

type wireEvent struct {
	up   bool
	size int
}

func (l *wireLog) add(up bool, size int) {
	l.mu.Lock()
	l.events = append(l.events, wireEvent{up, size})
	l.mu.Unlock()
}

func (l *wireLog) snapshot() []wireEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]wireEvent(nil), l.events...)
}

// morphPair connects a client end and a server end, both shaped by m, through a
// pipe that notes every frame in the order it is written.
func morphPair(t *testing.T, m *Morph) (client, server net.Conn, log *wireLog) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	log = &wireLog{}
	client = m.Wrap(&tapConn{Conn: a, onWrite: func(n int) { log.add(true, n) }}, Client)
	server = m.Wrap(&tapConn{Conn: b, onWrite: func(n int) { log.add(false, n) }}, Server)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server, log
}

func testOpening() []Opening {
	// Records are body lengths: a frame is 17 bytes smaller.
	return []Opening{{Steps: []OpeningStep{
		{Up: true, Len: 100 + tlsRecordOverhead},
		{Up: false, Len: 300 + tlsRecordOverhead},
		{Up: true, Len: 200 + tlsRecordOverhead},
		{Up: false, Len: 80 + tlsRecordOverhead},
	}}}
}

func TestMorphFollowsTheOpeningInOrder(t *testing.T) {
	m := NewMorph(MorphConfig{Openings: testOpening(), Idle: 5 * time.Millisecond})
	client, server, log := morphPair(t, m)

	got := make(chan []byte, 1)
	go func() {
		_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 5)
		_, _ = io.ReadFull(server, buf)
		got <- buf
	}()
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if data := <-got; string(data) != "hello" {
		t.Fatalf("the server read %q, want hello", data)
	}

	// The data took the client's first record. The rest of the opening is
	// filled by decoys, each end at its own turn.
	want := []wireEvent{{true, 100}, {false, 300}, {true, 200}, {false, 80}}
	waitUntil(t, 5*time.Second, func() bool { return len(log.snapshot()) >= len(want) })
	for i, w := range want {
		if got := log.snapshot()[i]; got != w {
			t.Errorf("frame %d = %+v, want %+v", i, got, w)
		}
	}
}

func waitUntil(t *testing.T, limit time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %v", limit)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestMorphCarriesDataBothWays(t *testing.T) {
	m := NewMorph(MorphConfig{Openings: testOpening(), Idle: 5 * time.Millisecond, Later: DefaultPadding})
	client, server, _ := morphPair(t, m)

	up := bytes.Repeat([]byte("up"), 4000)
	down := bytes.Repeat([]byte("down"), 3000)
	var wg sync.WaitGroup
	check := func(name string, from, to net.Conn, data []byte) {
		defer wg.Done()
		go func() { _, _ = from.Write(data) }()
		got := make([]byte, len(data))
		_ = to.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(to, got); err != nil {
			t.Errorf("%s: %v", name, err)
			return
		}
		if !bytes.Equal(got, data) {
			t.Errorf("%s: the data changed", name)
		}
	}
	wg.Add(2)
	go check("client to server", client, server, up)
	go check("server to client", server, client, down)
	wg.Wait()
}

// A new connection follows a different opening each time, so run several. A
// deadlock between the two ends would show here.
func TestMorphRoundTripWithTheEmbeddedOpenings(t *testing.T) {
	m, err := DefaultMorph()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 15; i++ {
		client, server, _ := morphPair(t, m)
		request := bytes.Repeat([]byte("q"), 700)
		reply := bytes.Repeat([]byte("r"), 5000)

		done := make(chan error, 1)
		go func() {
			buf := make([]byte, len(request))
			_ = server.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(server, buf); err != nil {
				done <- err
				return
			}
			_, err := server.Write(reply)
			done <- err
		}()
		if _, err := client.Write(request); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(reply))
		_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(client, got); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		if !bytes.Equal(got, reply) {
			t.Fatalf("round %d: the reply changed", i)
		}
		if err := <-done; err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
	}
}

func TestMorphRefusesADifferentListOfOpenings(t *testing.T) {
	two := append(testOpening(), testOpening()...)
	three := append(two, testOpening()...)
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	client := NewMorph(MorphConfig{Openings: two, Idle: 5 * time.Millisecond}).Wrap(a, Client)
	server := NewMorph(MorphConfig{Openings: three, Idle: 5 * time.Millisecond}).Wrap(b, Server)

	go func() { _, _ = client.Write([]byte("hello")) }()
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := server.Read(make([]byte, 5)); !errors.Is(err, errMorphTable) {
		t.Fatalf("Read = %v, want errMorphTable", err)
	}
}

func TestMorphReadHonoursItsDeadline(t *testing.T) {
	m := NewMorph(MorphConfig{Openings: testOpening(), Idle: time.Hour})
	_, server, _ := morphPair(t, m)

	_ = server.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	start := time.Now()
	_, err := server.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read = %v, want a deadline error", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the deadline took far too long")
	}
}

func TestMorphWithoutOpeningsFallsBackToPadding(t *testing.T) {
	m := NewMorph(MorphConfig{Later: DefaultPadding})
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	left, right := m.Wrap(a, Client), m.Wrap(b, Server)

	go func() { _, _ = left.Write([]byte("hello")) }()
	buf := make([]byte, 5)
	_ = right.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(right, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("read %q, %v", buf, err)
	}
}

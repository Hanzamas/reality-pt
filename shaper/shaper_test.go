package shaper

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestNoopReturnsSameConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	var s Shaper = Noop{}
	if got := s.Wrap(a); got != a {
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
	if got := Names(); len(got) != 2 || got[0] != "none" || got[1] != "padding" {
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
	return s.Wrap(tapped), s.Wrap(b), &sizes
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
	shaped := NewPadding(DefaultPadding).Wrap(b)

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

		shaped := NewPadding(DefaultPadding).Wrap(b)
		_ = shaped.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.Copy(io.Discard, shaped) // must not panic or hang
	})
}

package relay_test

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hanzamas/reality-pt/internal/pt/relay"
)

func TestPipeRelaysBothWaysAndClosesBothEnds(t *testing.T) {
	// clientEnd <-> a ... Pipe ... b <-> serverEnd
	clientEnd, a := net.Pipe()
	b, serverEnd := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		relay.Pipe(a, b)
	}()

	send(t, clientEnd, serverEnd, "ping")
	send(t, serverEnd, clientEnd, "pong")

	clientEnd.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Pipe did not return after one side closed")
	}

	_ = serverEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := serverEnd.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("far end read after Pipe returned: got %v, want io.EOF", err)
	}
}

// send writes msg to from and expects to read it back from to.
func send(t *testing.T, from, to net.Conn, msg string) {
	t.Helper()
	go func() { _, _ = from.Write([]byte(msg)) }()

	_ = to.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(to, buf); err != nil {
		t.Fatalf("read %q: %v", msg, err)
	}
	if string(buf) != msg {
		t.Fatalf("got %q, want %q", buf, msg)
	}
}

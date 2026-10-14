package shaper

import (
	"net"
	"testing"
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

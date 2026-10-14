// Package shaper defines the plug-in point for traffic shaping.
//
// A Shaper wraps the net.Conn that carries Tor traffic inside the tunnel,
// after the transport handshake has finished. Both client and server apply
// the same Shaper, so an implementation can pad, split, or delay writes and
// strip the padding again on read.
package shaper

import "net"

// Shaper wraps a connection with a traffic shaping layer.
type Shaper interface {
	// Wrap returns a connection that shapes what is written to c and undoes
	// the shaping on what is read. Closing the result must close c.
	Wrap(c net.Conn) net.Conn
}

// Noop is the default Shaper. It returns the connection unchanged.
type Noop struct{}

// Wrap implements Shaper.
func (Noop) Wrap(c net.Conn) net.Conn { return c }

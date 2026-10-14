// Package shaper defines the plug-in point for traffic shaping.
//
// A Shaper wraps the net.Conn that carries Tor traffic inside the tunnel,
// after the transport handshake has finished. Both client and server apply
// the same Shaper, so an implementation can pad, split, or delay writes and
// strip the padding again on read. The two ends must agree on the shaper: the
// server publishes its name in the bridge line.
package shaper

import (
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
)

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

// None is the name of the shaper that leaves traffic alone.
const None = "none"

var registry = map[string]Shaper{
	None:      Noop{},
	"padding": NewPadding(DefaultPadding),
}

// ByName returns the shaper registered under name. An empty name means None.
func ByName(name string) (Shaper, error) {
	if name == "" {
		name = None
	}
	s, ok := registry[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unknown shaper %q, supported: %s", name, strings.Join(Names(), ", "))
	}
	return s, nil
}

// Names returns the registered shaper names in sorted order.
func Names() []string { return slices.Sorted(maps.Keys(registry)) }

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

// Role says which end of the tunnel a Shaper wraps. A shaper that follows the
// pattern of a real connection needs it, because each end sends its own half.
type Role int

const (
	// Client is the end that dials the bridge.
	Client Role = iota
	// Server is the bridge.
	Server
)

// Shaper wraps a connection with a traffic shaping layer.
type Shaper interface {
	// Wrap returns a connection that shapes what is written to c and undoes
	// the shaping on what is read. Closing the result must close c.
	Wrap(c net.Conn, role Role) net.Conn
}

// Noop is a Shaper that returns the connection unchanged.
type Noop struct{}

// Wrap implements Shaper.
func (Noop) Wrap(c net.Conn, _ Role) net.Conn { return c }

// None is the name of the shaper that leaves traffic alone.
const None = "none"

var registry = func() map[string]Shaper {
	morph, err := DefaultMorph()
	if err != nil {
		// The data is embedded, so this is a build problem and a test catches it.
		panic("shaper: embedded openings: " + err.Error())
	}
	return map[string]Shaper{
		None:      Noop{},
		"padding": NewPadding(DefaultPadding),
		"morph":   morph,
	}
}()

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

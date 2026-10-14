// Package transport defines the stages a pluggable transport is assembled
// from. The PT runners in internal/ptclient and internal/ptserver know only
// these interfaces, so a new transport plugs in without touching them.
package transport

import (
	"context"
	"net"
)

// Args gives read access to key/value arguments. goptlib's pt.Args satisfies
// it, so bridge line and server option values flow in without conversion.
type Args interface {
	Get(key string) (value string, ok bool)
}

// ClientStage turns a raw connection to the bridge into a tunnel connection.
type ClientStage interface {
	// Handshake runs the transport handshake over raw. On error the caller
	// still owns raw and must close it.
	Handshake(ctx context.Context, raw net.Conn) (net.Conn, error)
}

// ClientFactory builds a ClientStage from the arguments of one bridge line.
type ClientFactory func(Args) (ClientStage, error)

// ServerStage accepts tunnel connections on a bridge.
type ServerStage interface {
	// Listen wraps a TCP listener so that Accept yields tunnel connections.
	Listen(inner net.Listener) net.Listener
	// PublicArgs returns the arguments a client needs, for the bridge line.
	// It must never include secrets.
	PublicArgs() map[string][]string
}

// ServerFactory builds a ServerStage from the server transport options.
type ServerFactory func(Args) (ServerStage, error)

// Package reality is a REALITY-style transport for Tor.
//
// The bridge answers every connection that does not prove knowledge of the
// bridge's X25519 public key and a short ID with the real TLS handshake of a
// cover site, so an active prober sees that site and not a proxy. A client
// that holds the key gets a TLS 1.3 tunnel whose ClientHello is shaped by
// uTLS to look like a browser.
//
// The server side wraps github.com/xtls/reality. The client side follows the
// REALITY client in Xray-core and is MPL-2.0 licensed, see client.go.
package reality

// Name is the transport name used in torrc and in bridge lines.
const Name = "reality"

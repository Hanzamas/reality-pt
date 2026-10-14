package reality

import (
	"fmt"
	"net"
	"strings"

	"github.com/hanzamas/reality-pt/transport"
)

// Names of the key/value arguments in a bridge line.
const (
	argPublicKey   = "public-key"
	argShortID     = "short-id"
	argServerName  = "sni"
	argFingerprint = "fingerprint"
)

// ClientParams is everything a client needs to reach one bridge.
type ClientParams struct {
	// PublicKey is the bridge's X25519 public key.
	PublicKey [keyLen]byte
	// ShortID must be one of the short IDs the bridge accepts.
	ShortID ShortID
	// ServerName is the SNI of the cover site, in lower case.
	ServerName string
	// Fingerprint names the uTLS ClientHello profile. Empty means
	// DefaultFingerprint.
	Fingerprint string
}

// ParseClientParams reads ClientParams from the arguments of a bridge line.
func ParseClientParams(args transport.Args) (ClientParams, error) {
	var p ClientParams

	rawKey, err := required(args, argPublicKey)
	if err != nil {
		return p, err
	}
	key, err := decodeKey(rawKey)
	if err != nil {
		return p, fmt.Errorf("reality: %s: %w", argPublicKey, err)
	}
	copy(p.PublicKey[:], key)

	rawID, err := required(args, argShortID)
	if err != nil {
		return p, err
	}
	if p.ShortID, err = ParseShortID(rawID); err != nil {
		return p, fmt.Errorf("reality: %s: %w", argShortID, err)
	}

	rawName, err := required(args, argServerName)
	if err != nil {
		return p, err
	}
	if p.ServerName, err = normalizeServerName(rawName); err != nil {
		return p, fmt.Errorf("reality: %s: %w", argServerName, err)
	}

	p.Fingerprint = DefaultFingerprint
	if v, ok := args.Get(argFingerprint); ok && v != "" {
		p.Fingerprint = strings.ToLower(v)
	}
	if _, err := lookupFingerprint(p.Fingerprint); err != nil {
		return p, fmt.Errorf("reality: %s: %w", argFingerprint, err)
	}
	return p, nil
}

// required returns the value of a mandatory argument.
func required(args transport.Args, key string) (string, error) {
	v, ok := args.Get(key)
	if !ok || v == "" {
		return "", fmt.Errorf("reality: missing %q argument", key)
	}
	return v, nil
}

// normalizeServerName lower-cases a cover site name and rejects values that
// are not valid SNI host names.
func normalizeServerName(s string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(s))
	switch {
	case name == "" || len(name) > 253:
		return "", fmt.Errorf("server name must be 1 to 253 characters")
	case strings.ContainsAny(name, " \t/:@"):
		return "", fmt.Errorf("server name must be a bare host name")
	case net.ParseIP(name) != nil:
		return "", fmt.Errorf("server name must not be an IP address")
	}
	return name, nil
}

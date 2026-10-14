package reality

import (
	"crypto/ecdh"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hanzamas/reality-pt/transport"
)

// Names of the server transport options in torrc.
const (
	optPrivateKey  = "private-key"
	optDest        = "dest"
	optServerNames = "server-names"
	optShortIDs    = "short-ids"
	optMaxTimeDiff = "max-time-diff"
)

// ServerParams configures a bridge.
type ServerParams struct {
	// PrivateKey is the bridge's X25519 private key.
	PrivateKey *ecdh.PrivateKey
	// Dest is the cover site as host:port. Connections that fail
	// authentication are forwarded there.
	Dest string
	// ServerNames lists the SNI values a client may use. All of them must be
	// served by Dest.
	ServerNames []string
	// ShortIDs lists the short IDs clients may present.
	ShortIDs []ShortID
	// MaxTimeDiff bounds the clock difference between client and bridge.
	// Zero disables the check.
	MaxTimeDiff time.Duration
}

// ParseServerParams reads ServerParams from the server transport options.
func ParseServerParams(args transport.Args) (ServerParams, error) {
	var p ServerParams

	rawKey, err := required(args, optPrivateKey)
	if err != nil {
		return p, err
	}
	key, err := decodeKey(rawKey)
	if err != nil {
		return p, fmt.Errorf("reality: %s: %w", optPrivateKey, err)
	}
	if p.PrivateKey, err = ecdh.X25519().NewPrivateKey(key); err != nil {
		return p, fmt.Errorf("reality: %s: %w", optPrivateKey, err)
	}

	if p.Dest, err = required(args, optDest); err != nil {
		return p, err
	}
	if _, port, err := net.SplitHostPort(p.Dest); err != nil || port == "" {
		return p, fmt.Errorf("reality: %s must be host:port", optDest)
	}

	names, err := requiredList(args, optServerNames)
	if err != nil {
		return p, err
	}
	for _, name := range names {
		n, err := normalizeServerName(name)
		if err != nil {
			return p, fmt.Errorf("reality: %s: %w", optServerNames, err)
		}
		p.ServerNames = append(p.ServerNames, n)
	}

	ids, err := requiredList(args, optShortIDs)
	if err != nil {
		return p, err
	}
	for _, raw := range ids {
		id, err := ParseShortID(raw)
		if err != nil {
			return p, fmt.Errorf("reality: %s: %w", optShortIDs, err)
		}
		p.ShortIDs = append(p.ShortIDs, id)
	}

	if v, ok := args.Get(optMaxTimeDiff); ok && v != "" {
		if p.MaxTimeDiff, err = time.ParseDuration(v); err != nil || p.MaxTimeDiff < 0 {
			return p, fmt.Errorf("reality: %s must be a non-negative duration such as 2m", optMaxTimeDiff)
		}
	}
	return p, nil
}

// PublicArgs returns the values a client needs for its bridge line. It lists
// the first server name and short ID only, and never the private key.
func (p ServerParams) PublicArgs() map[string][]string {
	return map[string][]string{
		argPublicKey:  {EncodeKey(p.PrivateKey.PublicKey().Bytes())},
		argShortID:    {p.ShortIDs[0].String()},
		argServerName: {p.ServerNames[0]},
	}
}

// requiredList returns the non-empty items of a comma-separated argument.
func requiredList(args transport.Args, key string) ([]string, error) {
	raw, err := required(args, key)
	if err != nil {
		return nil, err
	}
	var items []string
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("reality: %q must list at least one value", key)
	}
	return items, nil
}

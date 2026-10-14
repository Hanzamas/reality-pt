package reality

import (
	"crypto/ecdh"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/hanzamas/reality-pt/shaper"
	"github.com/hanzamas/reality-pt/transport"
)

// Names of the server transport options in torrc.
const (
	optPrivateKey       = "private-key"
	optDest             = "dest"
	optServerNames      = "server-names"
	optShortIDs         = "short-ids"
	optMaxTimeDiff      = "max-time-diff"
	optMinClientVersion = "min-client-version"
	optMaxClientVersion = "max-client-version"
	optProxyProtocol    = "proxy-protocol"
	optFallbackAfter    = "fallback-after"
	optFallbackRate     = "fallback-rate"
	optFallbackBurst    = "fallback-burst"
	optShaper           = "shaper"
)

// DefaultMaxTimeDiff is how far a client clock may differ from the bridge
// clock. Tor itself needs a clock within a few hours, so five minutes only
// turns away clients that were already broken.
const DefaultMaxTimeDiff = 5 * time.Minute

// FallbackLimit caps what one connection may move to or from the cover site,
// so the bridge cannot serve as a free relay to that site. The limit applies
// to each direction. A zero BytesPerSec turns it off.
type FallbackLimit struct {
	// AfterBytes pass at full speed before the rate applies.
	AfterBytes uint64
	// BytesPerSec is the sustained rate after that.
	BytesPerSec uint64
	// BurstBytesPerSec is the bucket size. Values below BytesPerSec count as
	// BytesPerSec.
	BurstBytesPerSec uint64
}

// DefaultFallbackLimit lets a prober fetch an ordinary page and slows anything
// bulkier.
var DefaultFallbackLimit = FallbackLimit{
	AfterBytes:       2 << 20,
	BytesPerSec:      1 << 20,
	BurstBytesPerSec: 2 << 20,
}

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
	// MinClientVersion and MaxClientVersion, when set, turn away clients
	// outside that range of protocol versions.
	MinClientVersion, MaxClientVersion *Version
	// ProxyProtocol is 1 or 2 to send a PROXY protocol header to the cover
	// site, 0 to send none. Use it when the cover site is yours and logs
	// client addresses.
	ProxyProtocol byte
	// FallbackLimit applies to forwarding to the cover site.
	FallbackLimit FallbackLimit
	// Shaper names the traffic shaper for every tunnel. Clients learn it from
	// the bridge line. Empty means none.
	Shaper string
}

// DefaultShaper is what a bridge uses unless its operator picks another.
const DefaultShaper = "padding"

// ParseServerParams reads ServerParams from the server transport options.
func ParseServerParams(args transport.Args) (ServerParams, error) {
	p := ServerParams{
		MaxTimeDiff:   DefaultMaxTimeDiff,
		FallbackLimit: DefaultFallbackLimit,
		Shaper:        DefaultShaper,
	}

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
			return p, fmt.Errorf("reality: %s must be a non-negative duration such as 2m, or 0 to turn the check off", optMaxTimeDiff)
		}
	}
	if p.MinClientVersion, err = optionalVersion(args, optMinClientVersion); err != nil {
		return p, err
	}
	if p.MaxClientVersion, err = optionalVersion(args, optMaxClientVersion); err != nil {
		return p, err
	}
	if v, ok := args.Get(optProxyProtocol); ok && v != "" {
		if v != "1" && v != "2" {
			return p, fmt.Errorf("reality: %s must be 1 or 2", optProxyProtocol)
		}
		p.ProxyProtocol = v[0] - '0'
	}
	if err := parseFallbackLimit(args, &p.FallbackLimit); err != nil {
		return p, err
	}
	if v, ok := args.Get(optShaper); ok && v != "" {
		p.Shaper = strings.ToLower(v)
	}
	if _, err := shaper.ByName(p.Shaper); err != nil {
		return p, fmt.Errorf("reality: %s: %w", optShaper, err)
	}
	return p, nil
}

// PublicArgs returns the values a client needs for its bridge line. It lists
// the first server name and short ID only, and never the private key.
func (p ServerParams) PublicArgs() map[string][]string {
	args := map[string][]string{
		argPublicKey:  {EncodeKey(p.PrivateKey.PublicKey().Bytes())},
		argShortID:    {p.ShortIDs[0].String()},
		argServerName: {p.ServerNames[0]},
	}
	if p.Shaper != "" {
		args[argShaper] = []string{p.Shaper}
	}
	return args
}

// optionalVersion reads a version argument. It returns nil if absent.
func optionalVersion(args transport.Args, key string) (*Version, error) {
	raw, ok := args.Get(key)
	if !ok || raw == "" {
		return nil, nil
	}
	v, err := ParseVersion(raw)
	if err != nil {
		return nil, fmt.Errorf("reality: %s: %w", key, err)
	}
	return &v, nil
}

// parseFallbackLimit overrides the fields of limit that the arguments set.
func parseFallbackLimit(args transport.Args, limit *FallbackLimit) error {
	for _, field := range []struct {
		key string
		dst *uint64
	}{
		{optFallbackAfter, &limit.AfterBytes},
		{optFallbackRate, &limit.BytesPerSec},
		{optFallbackBurst, &limit.BurstBytesPerSec},
	} {
		raw, ok := args.Get(field.key)
		if !ok || raw == "" {
			continue
		}
		n, err := strconv.ParseUint(raw, 10, 63)
		if err != nil {
			return fmt.Errorf("reality: %s must be a number of bytes", field.key)
		}
		*field.dst = n
	}
	return nil
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

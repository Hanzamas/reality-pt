package reality

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// DefaultFingerprint is the ClientHello profile used when a bridge line does
// not name one.
const DefaultFingerprint = "chrome"

// fingerprints maps profile names to uTLS ClientHello IDs. The REALITY server
// only accepts a ClientHello that offers an X25519MLKEM768 key share and puts
// a 32-byte session ID in it, so a profile belongs here only if
// TestEveryFingerprintCompletesAHandshake passes for it.
//
// The names without a version follow the newest profile uTLS ships for that
// browser. Pinned names stay available for bridges that must keep working
// while a newer profile is being checked.
var fingerprints = map[string]utls.ClientHelloID{
	"chrome":     utls.HelloChrome_Auto,
	"chrome-133": utls.HelloChrome_133,
	"chrome-131": utls.HelloChrome_131,
	"firefox":    utls.HelloFirefox_Auto,
	"safari":     utls.HelloSafari_Auto,
}

// Fingerprints returns the supported profile names in sorted order.
func Fingerprints() []string {
	return slices.Sorted(maps.Keys(fingerprints))
}

func lookupFingerprint(name string) (utls.ClientHelloID, error) {
	id, ok := fingerprints[strings.ToLower(name)]
	if !ok {
		return utls.ClientHelloID{}, fmt.Errorf("unknown fingerprint %q, supported: %s",
			name, strings.Join(Fingerprints(), ", "))
	}
	return id, nil
}

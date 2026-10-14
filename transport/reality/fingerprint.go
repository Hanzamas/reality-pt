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
// A profile must also track its browser. TestBrowserProfilesAreFresh checks
// that weekly and fails when a profile trails the browser by more than a few
// releases, because an old profile is a fingerprint of its own. Firefox is
// left out for that reason: uTLS has no profile for a recent Firefox yet. Add
// it back when it does. Safari has no automatic check.
var fingerprints = map[string]utls.ClientHelloID{
	"chrome": utls.HelloChrome_Auto,
	"safari": utls.HelloSafari_Auto,
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

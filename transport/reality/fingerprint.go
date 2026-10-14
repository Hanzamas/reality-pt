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
// only accepts a ClientHello that offers an X25519MLKEM768 key share, so add a
// profile only after checking that it does.
var fingerprints = map[string]utls.ClientHelloID{
	"chrome": utls.HelloChrome_Auto,
}

func lookupFingerprint(name string) (utls.ClientHelloID, error) {
	id, ok := fingerprints[strings.ToLower(name)]
	if !ok {
		return utls.ClientHelloID{}, fmt.Errorf("unknown fingerprint %q, supported: %s",
			name, strings.Join(slices.Sorted(maps.Keys(fingerprints)), ", "))
	}
	return id, nil
}

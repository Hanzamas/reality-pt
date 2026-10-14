package reality

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a three-part handshake version, written major.minor.patch.
type Version [3]byte

// ProtocolVersion is the version a client puts in its token. Bump it when the
// handshake changes in a way old clients cannot follow, and use the server's
// min-client-version option to turn them away.
var ProtocolVersion = Version{0, 1, 0}

// ParseVersion parses "major.minor.patch" with each part in 0 to 255.
func ParseVersion(s string) (Version, error) {
	var v Version
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != len(v) {
		return v, fmt.Errorf("version must look like 1.2.3, got %q", s)
	}
	for i, part := range parts {
		n, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return v, fmt.Errorf("version part %q is not a number from 0 to 255", part)
		}
		v[i] = byte(n)
	}
	return v, nil
}

// String returns the version as major.minor.patch.
func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }

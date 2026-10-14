package reality

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const keyLen = 32

// ShortID is the 8-byte identifier a client presents to the bridge. It is
// written as 2 to 16 hex digits and left-aligned, so "ab" and
// "ab00000000000000" are the same ID.
type ShortID [8]byte

// ParseShortID parses a short ID from hex.
func ParseShortID(s string) (ShortID, error) {
	var id ShortID
	if n := len(s); n == 0 || n > 2*len(id) || n%2 != 0 {
		return id, fmt.Errorf("short ID must be 2 to 16 hex digits, got %d characters", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("short ID is not hex: %w", err)
	}
	copy(id[:], b)
	return id, nil
}

// String returns the ID as 16 hex digits.
func (id ShortID) String() string { return hex.EncodeToString(id[:]) }

// EncodeKey encodes an X25519 key as unpadded URL-safe base64, the format the
// Xray tools print.
func EncodeKey(key []byte) string { return base64.RawURLEncoding.EncodeToString(key) }

// decodeKey is the inverse of EncodeKey and checks the key length.
func decodeKey(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("key is not unpadded URL-safe base64: %w", err)
	}
	if len(b) != keyLen {
		return nil, fmt.Errorf("key must be %d bytes, got %d", keyLen, len(b))
	}
	return b, nil
}

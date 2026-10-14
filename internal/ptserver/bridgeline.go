package ptserver

import (
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Placeholders in the bridge line file. Only the operator knows the public
// address, and only Tor knows the identity fingerprint.
const (
	ipPlaceholder          = "<IP ADDRESS>"
	fingerprintPlaceholder = "<FINGERPRINT>"
)

// bridgeLine formats the line a client puts in torrc, with placeholders for
// the address and the fingerprint.
func bridgeLine(name string, listen net.Addr, args map[string][]string) string {
	_, port, err := net.SplitHostPort(listen.String())
	if err != nil {
		port = "<PORT>"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Bridge %s %s:%s %s", name, ipPlaceholder, port, fingerprintPlaceholder)
	for _, key := range slices.Sorted(maps.Keys(args)) {
		for _, value := range args[key] {
			fmt.Fprintf(&b, " %s=%s", key, value)
		}
	}
	return b.String()
}

// writeBridgeLine saves the bridge line as <state dir>/<name>_bridge_line.txt
// so an operator does not have to assemble it by hand.
func writeBridgeLine(stateDir, name, line string) error {
	return os.WriteFile(filepath.Join(stateDir, name+"_bridge_line.txt"), []byte(line+"\n"), 0o644)
}

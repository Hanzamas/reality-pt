package server

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBridgeLine(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 443}
	args := map[string][]string{
		"sni":        {"cover.example"},
		"public-key": {"KEY"},
		"short-id":   {"abcd000000000000"},
	}

	got := bridgeLine("reality", addr, args)
	want := "Bridge reality <IP ADDRESS>:443 <FINGERPRINT> public-key=KEY short-id=abcd000000000000 sni=cover.example"
	if got != want {
		t.Fatalf("bridgeLine =\n %q\nwant\n %q", got, want)
	}
}

func TestWriteBridgeLine(t *testing.T) {
	dir := t.TempDir()
	if err := writeBridgeLine(dir, "reality", "Bridge reality x"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "reality_bridge_line.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "Bridge reality x" {
		t.Fatalf("file content = %q", data)
	}
}

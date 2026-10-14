package reality_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/hanzamas/reality-pt/transport/reality"
)

// mapArgs is a transport.Args backed by a map.
type mapArgs map[string]string

func (m mapArgs) Get(key string) (string, bool) {
	v, ok := m[key]
	return v, ok
}

func TestParseClientParams(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)

	p, err := reality.ParseClientParams(mapArgs{
		"public-key": reality.EncodeKey(key),
		"short-id":   "abcd",
		"sni":        " Cover.Example ",
	})
	if err != nil {
		t.Fatalf("ParseClientParams: %v", err)
	}
	if !bytes.Equal(p.PublicKey[:], key) {
		t.Error("public key mismatch")
	}
	if want := (reality.ShortID{0xab, 0xcd}); p.ShortID != want {
		t.Errorf("short ID = %v, want %v", p.ShortID, want)
	}
	if p.ServerName != "cover.example" {
		t.Errorf("server name = %q, want cover.example", p.ServerName)
	}
	if p.Fingerprint != reality.DefaultFingerprint {
		t.Errorf("fingerprint = %q, want %q", p.Fingerprint, reality.DefaultFingerprint)
	}
}

func TestParseClientParamsRejects(t *testing.T) {
	good := func() mapArgs {
		return mapArgs{
			"public-key": reality.EncodeKey(bytes.Repeat([]byte{7}, 32)),
			"short-id":   "abcd",
			"sni":        "cover.example",
		}
	}
	tests := map[string]func(mapArgs){
		"missing public key":  func(a mapArgs) { delete(a, "public-key") },
		"short public key":    func(a mapArgs) { a["public-key"] = reality.EncodeKey(make([]byte, 16)) },
		"padded base64 key":   func(a mapArgs) { a["public-key"] += "=" },
		"missing short id":    func(a mapArgs) { delete(a, "short-id") },
		"odd length short id": func(a mapArgs) { a["short-id"] = "abc" },
		"long short id":       func(a mapArgs) { a["short-id"] = strings.Repeat("ab", 9) },
		"non-hex short id":    func(a mapArgs) { a["short-id"] = "zz" },
		"missing sni":         func(a mapArgs) { delete(a, "sni") },
		"ip as sni":           func(a mapArgs) { a["sni"] = "192.0.2.1" },
		"sni with port":       func(a mapArgs) { a["sni"] = "cover.example:443" },
		"unknown fingerprint": func(a mapArgs) { a["fingerprint"] = "netscape" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			args := good()
			mutate(args)
			if _, err := reality.ParseClientParams(args); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func newServerArgs(t *testing.T) (mapArgs, *ecdh.PrivateKey) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return mapArgs{
		"private-key":   reality.EncodeKey(priv.Bytes()),
		"dest":          "cover.example:443",
		"server-names":  "Cover.Example, www.cover.example",
		"short-ids":     "abcd, 0011223344556677",
		"max-time-diff": "2m",
	}, priv
}

func TestParseServerParams(t *testing.T) {
	args, priv := newServerArgs(t)

	p, err := reality.ParseServerParams(args)
	if err != nil {
		t.Fatalf("ParseServerParams: %v", err)
	}
	if !p.PrivateKey.Equal(priv) {
		t.Error("private key mismatch")
	}
	if p.Dest != "cover.example:443" {
		t.Errorf("dest = %q", p.Dest)
	}
	if got := strings.Join(p.ServerNames, ","); got != "cover.example,www.cover.example" {
		t.Errorf("server names = %q", got)
	}
	if len(p.ShortIDs) != 2 {
		t.Errorf("got %d short IDs, want 2", len(p.ShortIDs))
	}
	if p.MaxTimeDiff != 2*time.Minute {
		t.Errorf("max time diff = %v", p.MaxTimeDiff)
	}
}

func TestParseServerParamsRejects(t *testing.T) {
	tests := map[string]func(mapArgs){
		"missing private key": func(a mapArgs) { delete(a, "private-key") },
		"short private key":   func(a mapArgs) { a["private-key"] = reality.EncodeKey(make([]byte, 8)) },
		"dest without port":   func(a mapArgs) { a["dest"] = "cover.example" },
		"missing dest":        func(a mapArgs) { delete(a, "dest") },
		"empty server names":  func(a mapArgs) { a["server-names"] = " , " },
		"bad server name":     func(a mapArgs) { a["server-names"] = "a b" },
		"missing short ids":   func(a mapArgs) { delete(a, "short-ids") },
		"bad short id":        func(a mapArgs) { a["short-ids"] = "abcd,xyz" },
		"bad time diff":       func(a mapArgs) { a["max-time-diff"] = "soon" },
		"negative time diff":  func(a mapArgs) { a["max-time-diff"] = "-1m" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			args, _ := newServerArgs(t)
			mutate(args)
			if _, err := reality.ParseServerParams(args); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestPublicArgsNeverExposeThePrivateKey(t *testing.T) {
	args, priv := newServerArgs(t)
	p, err := reality.ParseServerParams(args)
	if err != nil {
		t.Fatal(err)
	}

	public := p.PublicArgs()
	if got, want := public["public-key"], []string{reality.EncodeKey(priv.PublicKey().Bytes())}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("public-key = %v, want %v", got, want)
	}
	secret := reality.EncodeKey(priv.Bytes())
	for k, values := range public {
		if k == "private-key" {
			t.Errorf("PublicArgs has a %q entry", k)
		}
		for _, v := range values {
			if strings.Contains(v, secret) {
				t.Errorf("PublicArgs[%q] contains the private key", k)
			}
		}
	}
}

// The values PublicArgs publishes must be accepted as client arguments.
func TestPublicArgsRoundTripIntoClientParams(t *testing.T) {
	args, _ := newServerArgs(t)
	p, err := reality.ParseServerParams(args)
	if err != nil {
		t.Fatal(err)
	}

	client := mapArgs{}
	for k, values := range p.PublicArgs() {
		client[k] = values[0]
	}
	cp, err := reality.ParseClientParams(client)
	if err != nil {
		t.Fatalf("client rejected the published arguments: %v", err)
	}
	if cp.ServerName != p.ServerNames[0] || cp.ShortID != p.ShortIDs[0] {
		t.Errorf("round trip changed the values: %+v", cp)
	}
}

func TestServerDefaults(t *testing.T) {
	args, _ := newServerArgs(t)
	delete(args, "max-time-diff")

	p, err := reality.ParseServerParams(args)
	if err != nil {
		t.Fatal(err)
	}
	if p.MaxTimeDiff != reality.DefaultMaxTimeDiff {
		t.Errorf("max time diff = %v, want the default %v", p.MaxTimeDiff, reality.DefaultMaxTimeDiff)
	}
	if p.FallbackLimit != reality.DefaultFallbackLimit {
		t.Errorf("fallback limit = %+v, want the default %+v", p.FallbackLimit, reality.DefaultFallbackLimit)
	}
	if p.MinClientVersion != nil || p.MaxClientVersion != nil || p.ProxyProtocol != 0 {
		t.Errorf("optional settings are not off by default: %+v", p)
	}
}

func TestServerOptionalSettings(t *testing.T) {
	args, _ := newServerArgs(t)
	args["max-time-diff"] = "0"
	args["min-client-version"] = "0.1.0"
	args["max-client-version"] = "1.255.3"
	args["proxy-protocol"] = "2"
	args["fallback-after"] = "100"
	args["fallback-rate"] = "0"

	p, err := reality.ParseServerParams(args)
	if err != nil {
		t.Fatal(err)
	}
	if p.MaxTimeDiff != 0 {
		t.Errorf("max-time-diff=0 did not turn the check off: %v", p.MaxTimeDiff)
	}
	if p.MinClientVersion == nil || *p.MinClientVersion != (reality.Version{0, 1, 0}) {
		t.Errorf("min client version = %v", p.MinClientVersion)
	}
	if p.MaxClientVersion == nil || *p.MaxClientVersion != (reality.Version{1, 255, 3}) {
		t.Errorf("max client version = %v", p.MaxClientVersion)
	}
	if p.ProxyProtocol != 2 {
		t.Errorf("proxy protocol = %d, want 2", p.ProxyProtocol)
	}
	if p.FallbackLimit.AfterBytes != 100 || p.FallbackLimit.BytesPerSec != 0 {
		t.Errorf("fallback limit = %+v", p.FallbackLimit)
	}
}

func TestServerRejectsBadOptionalSettings(t *testing.T) {
	tests := map[string]func(mapArgs){
		"version with two parts":      func(a mapArgs) { a["min-client-version"] = "1.2" },
		"version part above 255":      func(a mapArgs) { a["max-client-version"] = "1.2.256" },
		"version with a word":         func(a mapArgs) { a["min-client-version"] = "1.x.3" },
		"proxy protocol 3":            func(a mapArgs) { a["proxy-protocol"] = "3" },
		"proxy protocol word":         func(a mapArgs) { a["proxy-protocol"] = "yes" },
		"negative fallback rate":      func(a mapArgs) { a["fallback-rate"] = "-5" },
		"fallback after not a number": func(a mapArgs) { a["fallback-after"] = "lots" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			args, _ := newServerArgs(t)
			mutate(args)
			if _, err := reality.ParseServerParams(args); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestShaperArguments(t *testing.T) {
	args, _ := newServerArgs(t)

	// Absent: the bridge shapes its traffic and says so in the bridge line.
	p, err := reality.ParseServerParams(args)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.PublicArgs()["shaper"]; len(got) != 1 || got[0] != reality.DefaultShaper {
		t.Errorf("default shaper in PublicArgs = %v, want [%s]", got, reality.DefaultShaper)
	}

	// "none" turns it off, and the bridge line says that too.
	args["shaper"] = "none"
	if p, err = reality.ParseServerParams(args); err != nil {
		t.Fatal(err)
	}
	if got := p.PublicArgs()["shaper"]; len(got) != 1 || got[0] != "none" {
		t.Errorf("PublicArgs shaper = %v, want [none]", got)
	}

	// Set: the bridge line carries it, and the client accepts it.
	args["shaper"] = "Padding"
	p, err = reality.ParseServerParams(args)
	if err != nil {
		t.Fatal(err)
	}
	public := p.PublicArgs()
	if got := public["shaper"]; len(got) != 1 || got[0] != "padding" {
		t.Fatalf("PublicArgs shaper = %v, want [padding]", got)
	}
	client := mapArgs{}
	for k, values := range public {
		client[k] = values[0]
	}
	cp, err := reality.ParseClientParams(client)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Shaper != "padding" {
		t.Errorf("client shaper = %q", cp.Shaper)
	}

	// Unknown names are refused on both sides.
	args["shaper"] = "rot13"
	if _, err := reality.ParseServerParams(args); err == nil {
		t.Error("the server accepted an unknown shaper")
	}
	client["shaper"] = "rot13"
	if _, err := reality.ParseClientParams(client); err == nil {
		t.Error("the client accepted an unknown shaper")
	}
}

func TestVersion(t *testing.T) {
	v, err := reality.ParseVersion(" 1.20.255 ")
	if err != nil {
		t.Fatal(err)
	}
	if v != (reality.Version{1, 20, 255}) || v.String() != "1.20.255" {
		t.Fatalf("version = %v (%s)", [3]byte(v), v)
	}
}

func FuzzParseShortID(f *testing.F) {
	f.Add("abcd")
	f.Add("")
	f.Add("0011223344556677")
	f.Fuzz(func(t *testing.T, s string) {
		id, err := reality.ParseShortID(s)
		if err != nil {
			return
		}
		again, err := reality.ParseShortID(id.String())
		if err != nil || again != id {
			t.Fatalf("round trip of %q failed: %v %v", s, again, err)
		}
	})
}

func FuzzParseClientParams(f *testing.F) {
	key := reality.EncodeKey(bytes.Repeat([]byte{7}, 32))
	f.Add(key, "abcd", "cover.example", "chrome")
	f.Add("", "", "", "")
	f.Fuzz(func(t *testing.T, publicKey, shortID, sni, fingerprint string) {
		p, err := reality.ParseClientParams(mapArgs{
			"public-key":  publicKey,
			"short-id":    shortID,
			"sni":         sni,
			"fingerprint": fingerprint,
		})
		if err != nil {
			return
		}
		if p.ServerName == "" || p.ServerName != strings.ToLower(p.ServerName) {
			t.Fatalf("accepted a bad server name %q", p.ServerName)
		}
		if _, err := reality.NewClient(p); err != nil {
			t.Fatalf("accepted parameters that NewClient rejects: %v", err)
		}
	})
}

func FuzzParseServerParams(f *testing.F) {
	key := reality.EncodeKey(bytes.Repeat([]byte{7}, 32))
	f.Add(key, "cover.example:443", "cover.example", "abcd", "2m")
	f.Add("", "", "", "", "")
	f.Fuzz(func(t *testing.T, privateKey, dest, names, ids, maxDiff string) {
		p, err := reality.ParseServerParams(mapArgs{
			"private-key":   privateKey,
			"dest":          dest,
			"server-names":  names,
			"short-ids":     ids,
			"max-time-diff": maxDiff,
		})
		if err != nil {
			return
		}
		if len(p.ServerNames) == 0 || len(p.ShortIDs) == 0 || p.PrivateKey == nil {
			t.Fatalf("accepted incomplete parameters: %+v", p)
		}
		public := p.PublicArgs()
		for _, key := range []string{"public-key", "short-id", "sni"} {
			if len(public[key]) != 1 {
				t.Fatalf("PublicArgs is missing %q", key)
			}
		}
	})
}

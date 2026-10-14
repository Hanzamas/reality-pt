package doctor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func startSite(t *testing.T, minVersion, maxVersion uint16) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: minVersion, MaxVersion: maxVersion}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

func find(t *testing.T, r Report, name string) Check {
	t.Helper()
	for _, c := range r {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("report has no %q check: %+v", name, r)
	return Check{}
}

func TestGoodCover(t *testing.T) {
	srv, pool := startSite(t, tls.VersionTLS13, tls.VersionTLS13)

	report := Run(context.Background(), Options{
		Dest:       srv.Listener.Addr().String(),
		ServerName: "example.com",
		RootCAs:    pool,
		Timeout:    10 * time.Second,
	})
	if !report.OK() {
		t.Fatalf("a TLS 1.3 site failed: %+v", report)
	}
	for _, name := range []string{"connect", "tls 1.3", "key exchange"} {
		if c := find(t, report, name); c.Status != Pass {
			t.Errorf("%s: %v %s", name, c.Status, c.Detail)
		}
	}
}

func TestSiteWithoutTLS13Fails(t *testing.T) {
	srv, pool := startSite(t, tls.VersionTLS12, tls.VersionTLS12)

	report := Run(context.Background(), Options{
		Dest:       srv.Listener.Addr().String(),
		ServerName: "example.com",
		RootCAs:    pool,
		Timeout:    10 * time.Second,
	})
	if report.OK() {
		t.Fatalf("a TLS 1.2 site passed: %+v", report)
	}
	if c := find(t, report, "tls 1.3"); c.Status != Fail {
		t.Errorf("tls 1.3 check: %v %s", c.Status, c.Detail)
	}
}

func TestUntrustedCertificateOnlyWarns(t *testing.T) {
	srv, _ := startSite(t, tls.VersionTLS13, tls.VersionTLS13)

	report := Run(context.Background(), Options{
		Dest:       srv.Listener.Addr().String(),
		ServerName: "example.com",
		Timeout:    10 * time.Second,
	})
	if !report.OK() {
		t.Fatalf("a bad certificate failed the whole check: %+v", report)
	}
	if c := find(t, report, "certificate"); c.Status != Warn {
		t.Errorf("certificate check: %v %s", c.Status, c.Detail)
	}
}

func TestUnreachableSiteFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	report := Run(context.Background(), Options{Dest: addr, Timeout: 3 * time.Second})
	if report.OK() {
		t.Fatalf("an unreachable site passed: %+v", report)
	}
}

func TestBadDestination(t *testing.T) {
	if report := Run(context.Background(), Options{Dest: "no-port"}); report.OK() {
		t.Fatalf("a destination without a port passed: %+v", report)
	}
}

func TestCymruName(t *testing.T) {
	tests := map[string]string{
		"1.2.3.4":     "4.3.2.1.origin.asn.cymru.com",
		"2001:db8::1": "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com",
	}
	for in, want := range tests {
		got, err := cymruName(net.ParseIP(in))
		if err != nil || got != want {
			t.Errorf("cymruName(%s) = %q, %v; want %q", in, got, err, want)
		}
	}
}

type fakeResolver map[string][]string

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func TestOriginASN(t *testing.T) {
	r := fakeResolver{
		"4.3.2.1.origin.asn.cymru.com": {"13335 | 1.2.3.0/24 | US | arin | 2010-07-14"},
		"8.7.6.5.origin.asn.cymru.com": {"64500 64501 | 5.6.7.0/24 | ZZ | test | 2020-01-01"},
	}
	if asn, err := originASN(context.Background(), r, net.ParseIP("1.2.3.4")); err != nil || asn != "13335" {
		t.Errorf("asn = %q, %v", asn, err)
	}
	if asn, err := originASN(context.Background(), r, net.ParseIP("5.6.7.8")); err != nil || asn != "64500" {
		t.Errorf("multi-origin asn = %q, %v", asn, err)
	}
	if _, err := originASN(context.Background(), r, net.ParseIP("9.9.9.9")); err == nil {
		t.Error("an unknown address produced an ASN")
	}
}

func TestNetworkCheckWarnsOnMismatch(t *testing.T) {
	srv, pool := startSite(t, tls.VersionTLS13, tls.VersionTLS13)
	r := fakeResolver{
		"4.3.2.1.origin.asn.cymru.com":   {"64500 | 1.2.3.0/24 | ZZ | test | 2020-01-01"},
		"1.0.0.127.origin.asn.cymru.com": {"64999 | 127.0.0.0/8 | ZZ | test | 2020-01-01"},
	}

	report := Run(context.Background(), Options{
		Dest:       srv.Listener.Addr().String(),
		ServerName: "localhost",
		RootCAs:    pool,
		BridgeIP:   net.ParseIP("1.2.3.4"),
		Resolver:   r,
		Timeout:    10 * time.Second,
	})
	c := find(t, report, "network")
	if c.Status != Warn || !strings.Contains(c.Detail, "AS64500") {
		t.Errorf("network check: %v %s", c.Status, c.Detail)
	}
}

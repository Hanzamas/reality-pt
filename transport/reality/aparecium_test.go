package reality_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	xr "github.com/xtls/reality"

	"github.com/hanzamas/reality-pt/internal/measure/traffic"
	"github.com/hanzamas/reality-pt/transport/reality"
)

// coverCert is a certificate for coverSNI signed by a CA that the whole test
// binary trusts. The REALITY server learns the shape of the cover's handshake
// by connecting to it with certificate checks on, so a cover with a
// self-signed certificate teaches it nothing.
var coverCert tls.Certificate

func TestMain(m *testing.M) { os.Exit(runTests(m)) }

func runTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "reality-pt-ca")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)

	// The system roots are read once, so this has to happen before any test
	// opens a verified connection. Only Linux honours the variable.
	cert, caPEM, err := newCoverCert()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	coverCert = cert
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	os.Setenv("SSL_CERT_FILE", caFile)
	return m.Run()
}

func newCoverCert() (tls.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "reality-pt test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: coverSNI},
		DNSNames:     []string{coverSNI},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, caPEM, nil
}

// TestPostHandshakeRecordsMatchTheCover guards against the detection that the
// Aparecium tool is built on. A TLS 1.3 server sends session tickets right
// after the handshake. A proxy that copies the cover's handshake but not those
// records gives itself away: a prober sees records after the handshake from
// the cover and none from the bridge. The REALITY server measures the cover's
// records and replays their lengths, and this test checks that it does.
func TestPostHandshakeRecordsMatchTheCover(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the test cover site is trusted through SSL_CERT_FILE, which only Linux reads")
	}

	cover := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cover.EnableHTTP2 = true
	cover.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{coverCert}}
	cover.StartTLS()
	t.Cleanup(cover.Close)

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortID := reality.ShortID{0xab, 0xcd, 1, 2, 3, 4, 5, 6}
	// No shaper: it would add records of its own, and this test is about the
	// transport.
	server, err := reality.NewServer(reality.ServerParams{
		PrivateKey:  priv,
		Dest:        cover.Listener.Addr().String(),
		ServerNames: []string{coverSNI},
		ShortIDs:    []reality.ShortID{shortID},
		Shaper:      "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := server.Listen(inner)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(io.Discard, conn) }()
		}
	}()

	// The server measures the cover in the background. Wait for the result for
	// the profile a Chrome client uses (h2).
	key := cover.Listener.Addr().String() + " " + coverSNI + " 2"
	waitFor(t, 30*time.Second, func() bool {
		lens, ok := xr.GlobalPostHandshakeRecordsLens.Load(key)
		records, isList := lens.([]int)
		return ok && isList && len(records) > 0
	})

	params := reality.ClientParams{ServerName: coverSNI, ShortID: shortID}
	copy(params.PublicKey[:], priv.PublicKey().Bytes())

	viaBridge := idleSession(t, inner.Addr().String(), func(raw net.Conn) (net.Conn, error) {
		client, err := reality.NewClient(params)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()
		return client.Handshake(ctx, raw)
	})
	direct := idleSession(t, cover.Listener.Addr().String(), func(raw net.Conn) (net.Conn, error) {
		conn := tls.Client(raw, &tls.Config{ServerName: coverSNI, InsecureSkipVerify: true, NextProtos: []string{"h2"}})
		return conn, conn.Handshake()
	})

	t.Logf("records after the handshake, from the cover: %v, from the bridge: %v", direct, viaBridge)
	if len(direct) == 0 {
		t.Fatal("the cover sent nothing after its handshake, so the test shows nothing")
	}
	if len(viaBridge) != len(direct) {
		t.Fatalf("the bridge sent %d records after the handshake, the cover sent %d", len(viaBridge), len(direct))
	}
	for i := range direct {
		if viaBridge[i] != direct[i] {
			t.Errorf("record %d: the bridge sent %d bytes, the cover sent %d", i, viaBridge[i], direct[i])
		}
	}
}

// idleSession connects through a tap, completes the handshake, stays quiet for
// a moment so the server can send what it sends unasked, and returns the
// lengths of the records the server sent after the client's Finished.
func idleSession(t *testing.T, target string, handshake func(net.Conn) (net.Conn, error)) []int {
	t.Helper()
	tap := traffic.StartTap(t, target)
	raw, err := net.DialTimeout("tcp", tap.Addr, testTimeout)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := handshake(raw)
	if err != nil {
		_ = raw.Close()
		t.Fatalf("handshake: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	_, _ = conn.Read(make([]byte, 1)) // lets a TLS client process post-handshake messages
	_ = conn.Close()

	// Our own close makes the server answer with a close_notify alert, an
	// encrypted record of 19 bytes. Whether it gets out before the TCP close
	// is a matter of timing, so it is left out.
	const closeNotifyLen = 19
	var lens []int
	for _, step := range traffic.AfterHandshake(tap.Wait(testTimeout)) {
		if !step.Up && step.Len != closeNotifyLen {
			lens = append(lens, step.Len)
		}
	}
	return lens
}

func waitFor(t *testing.T, limit time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %v", limit)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

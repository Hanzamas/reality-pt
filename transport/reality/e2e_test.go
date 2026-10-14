package reality_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hanzamas/reality-pt/transport/reality"
)

const (
	coverSNI    = "cover.test"
	testTimeout = 30 * time.Second
)

// bridge is a REALITY server in front of a local TLS 1.3 cover site. Clients
// that authenticate reach an echo service. Everyone else reaches the cover.
type bridge struct {
	addr    string
	cover   *httptest.Server
	public  [32]byte
	shortID reality.ShortID
}

func startBridge(t *testing.T) *bridge {
	t.Helper()

	cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "cover site")
	}))
	cover.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	cover.StartTLS()
	t.Cleanup(cover.Close)

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := &bridge{cover: cover, shortID: reality.ShortID{0xab, 0xcd, 1, 2, 3, 4, 5, 6}}
	copy(b.public[:], priv.PublicKey().Bytes())

	server := reality.NewServer(reality.ServerParams{
		PrivateKey:  priv,
		Dest:        cover.Listener.Addr().String(),
		ServerNames: []string{coverSNI},
		ShortIDs:    []reality.ShortID{b.shortID},
	})
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := server.Listen(inner)
	t.Cleanup(func() { _ = ln.Close() })
	b.addr = inner.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return b
}

func (b *bridge) params() reality.ClientParams {
	return reality.ClientParams{PublicKey: b.public, ShortID: b.shortID, ServerName: coverSNI}
}

func dial(t *testing.T, b *bridge, p reality.ClientParams) (net.Conn, error) {
	t.Helper()
	client, err := reality.NewClient(p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.DialTimeout("tcp", b.addr, testTimeout)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	conn, err := client.Handshake(ctx, raw)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, nil
}

func TestHandshakeAndEcho(t *testing.T) {
	b := startBridge(t)

	conn, err := dial(t, b, b.params())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(testTimeout))

	msg := []byte("tor cell goes here")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

func TestWrongKeyIsRejected(t *testing.T) {
	b := startBridge(t)

	p := b.params()
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	copy(p.PublicKey[:], other.PublicKey().Bytes())

	if _, err := dial(t, b, p); !errors.Is(err, reality.ErrNotBridge) {
		t.Fatalf("handshake with a wrong key: got %v, want ErrNotBridge", err)
	}
}

func TestWrongShortIDIsRejected(t *testing.T) {
	b := startBridge(t)

	p := b.params()
	p.ShortID = reality.ShortID{0xff}

	if _, err := dial(t, b, p); !errors.Is(err, reality.ErrNotBridge) {
		t.Fatalf("handshake with a wrong short ID: got %v, want ErrNotBridge", err)
	}
}

// A prober that knows nothing must see the cover site, not a proxy.
func TestProbeSeesTheCoverSite(t *testing.T) {
	b := startBridge(t)

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: testTimeout}, "tcp", b.addr, &tls.Config{
		ServerName:         coverSNI,
		InsecureSkipVerify: true, // the cover certificate is self-signed
	})
	if err != nil {
		t.Fatalf("probe handshake: %v", err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("probe received no certificate")
	}
	if !certs[0].Equal(b.cover.Certificate()) {
		t.Fatal("probe did not receive the cover site's certificate")
	}
}

// Every profile in the table must get through the real server, which is
// stricter about the ClientHello than a normal TLS server.
func TestEveryFingerprintCompletesAHandshake(t *testing.T) {
	b := startBridge(t)

	for _, name := range reality.Fingerprints() {
		t.Run(name, func(t *testing.T) {
			p := b.params()
			p.Fingerprint = name

			conn, err := dial(t, b, p)
			if err != nil {
				t.Fatalf("handshake with fingerprint %q: %v", name, err)
			}
			_ = conn.SetDeadline(time.Now().Add(testTimeout))
			if _, err := conn.Write([]byte("x")); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
				t.Fatalf("read: %v", err)
			}
		})
	}
}

// An active prober must not be able to tell the bridge from the cover site:
// each probe gets the same answer from both.
func TestProbesGetTheSameAnswerAsTheCoverSite(t *testing.T) {
	b := startBridge(t)
	coverAddr := b.cover.Listener.Addr().String()

	probes := map[string][]byte{
		"HTTP request":      []byte("GET / HTTP/1.1\r\nHost: cover.test\r\n\r\n"),
		"garbage":           bytes.Repeat([]byte{0xa5}, 64),
		"truncated TLS":     {0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00},
		"empty connection":  nil,
		"TLS alert record":  {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},
		"unknown record":    {0x63, 0x03, 0x03, 0x00, 0x01, 0x00},
		"oversized length":  {0x16, 0x03, 0x01, 0xff, 0xff},
		"SSLv2-style hello": {0x80, 0x2e, 0x01, 0x03, 0x01},
	}
	for name, payload := range probes {
		t.Run(name, func(t *testing.T) {
			viaBridge := probe(t, b.addr, payload)
			direct := probe(t, coverAddr, payload)
			if !bytes.Equal(viaBridge, direct) {
				t.Fatalf("answers differ\n via bridge: %q\n from cover:  %q", viaBridge, direct)
			}
		})
	}
}

// probe sends payload, half-closes, and returns everything the peer sends
// back until it closes or goes quiet.
func probe(t *testing.T, addr string, payload []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, testTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write probe: %v", err)
		}
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	answer, _ := io.ReadAll(conn)
	return answer
}

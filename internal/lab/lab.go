// Package lab builds small local copies of the real setup so that tests can
// measure the traffic a censor would see. It stands up a REALITY bridge in
// front of a TLS 1.3 cover site, with a TLS server behind it that plays the
// part of Tor's link, and an ordinary HTTP/2 site to compare against.
package lab

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hanzamas/reality-pt/internal/relay"
	"github.com/hanzamas/reality-pt/internal/traffic"
	"github.com/hanzamas/reality-pt/transport/reality"
)

const (
	// SNI is the server name of the cover site.
	SNI = "cover.test"
	// CellLen is the size of a Tor cell.
	CellLen = 514

	timeout = 30 * time.Second
)

// Bridge is a running REALITY server with a Tor-like link behind it.
type Bridge struct {
	// Addr is where clients connect.
	Addr string
	// Params are the client parameters for this bridge, shaper included.
	Params reality.ClientParams
}

// StartBridge starts a bridge that uses the named shaper.
func StartBridge(t testing.TB, shaperName string) *Bridge {
	t.Helper()

	cover := startTLSSite(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "cover site")
	}))
	link := startLink(t)

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortID := reality.ShortID{0xab, 0xcd, 1, 2, 3, 4, 5, 6}
	server, err := reality.NewServer(reality.ServerParams{
		PrivateKey:  priv,
		Dest:        cover.Listener.Addr().String(),
		ServerNames: []string{SNI},
		ShortIDs:    []reality.ShortID{shortID},
		Shaper:      shaperName,
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
			go func() {
				or, err := net.Dial("tcp", link)
				if err != nil {
					_ = conn.Close()
					return
				}
				relay.Pipe(server.Shaper().Wrap(conn), or)
			}()
		}
	}()

	b := &Bridge{
		Addr:   inner.Addr().String(),
		Params: reality.ClientParams{ServerName: SNI, ShortID: shortID, Shaper: shaperName},
	}
	copy(b.Params.PublicKey[:], priv.PublicKey().Bytes())
	return b
}

// TorLikeSession connects to the bridge through a tap and does what a Tor
// client does over a new link: a TLS handshake inside the tunnel, then a run
// of 514-byte cells with echoes coming back. It returns the application data
// records the tap saw after the tunnel's own handshake.
func (b *Bridge) TorLikeSession(t testing.TB, rng *mrand.Rand) []traffic.Step {
	t.Helper()
	tap := traffic.StartTap(t, b.Addr)

	client, err := reality.NewClient(b.Params)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.DialTimeout("tcp", tap.Addr, timeout)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	tunnel, err := client.Handshake(ctx, raw)
	if err != nil {
		_ = raw.Close()
		t.Fatalf("tunnel handshake: %v", err)
	}
	conn := client.Shaper().Wrap(tunnel)

	link := tls.Client(conn, &tls.Config{ServerName: "link.test", InsecureSkipVerify: true})
	_ = link.SetDeadline(time.Now().Add(timeout))
	if err := link.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		t.Fatalf("link handshake: %v", err)
	}

	cell := make([]byte, CellLen)
	echo := make([]byte, CellLen)
	for cells := 8 + rng.IntN(32); cells > 0; {
		burst := min(1+rng.IntN(4), cells)
		for i := 0; i < burst; i++ {
			if _, err := link.Write(cell); err != nil {
				t.Fatalf("write cell: %v", err)
			}
		}
		for i := 0; i < burst; i++ {
			if _, err := io.ReadFull(link, echo); err != nil {
				t.Fatalf("read cell: %v", err)
			}
		}
		cells -= burst
		time.Sleep(time.Duration(rng.IntN(3)) * time.Millisecond)
	}
	_ = link.Close()
	_ = conn.Close()
	return traffic.AfterHandshake(tap.Wait(timeout))
}

// Browsing is an ordinary HTTP/2 site and a way to visit it through a tap.
type Browsing struct {
	server *httptest.Server
}

// StartBrowsing starts a TLS 1.3 HTTP/2 site that answers with a body of the
// size asked for in the "n" query parameter.
func StartBrowsing(t testing.TB) *Browsing {
	t.Helper()
	return &Browsing{server: startTLSSite(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := 0
		for _, c := range r.URL.Query().Get("n") {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		_, _ = w.Write(make([]byte, min(n, 1<<20)))
		_, _ = io.Copy(io.Discard, r.Body)
	}))}
}

// Visit loads a few pages and resources through a tap, as a browser would,
// and returns the application data records the tap saw after the handshake.
func (b *Browsing) Visit(t testing.TB, rng *mrand.Rand) []traffic.Step {
	t.Helper()
	tap := traffic.StartTap(t, b.server.Listener.Addr().String())

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   &tls.Config{ServerName: SNI, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, tap.Addr)
			},
		},
	}
	for requests := 3 + rng.IntN(6); requests > 0; requests-- {
		// Sizes from 400 bytes to 300 KB, spread evenly on a log scale.
		size := int(400 * math.Exp(rng.Float64()*math.Log(300_000.0/400)))
		url := "https://" + SNI + "/page?n=" + itoa(size)
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	client.CloseIdleConnections()
	return traffic.AfterHandshake(tap.Wait(timeout))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for ; n > 0; n /= 10 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
	}
	return string(digits)
}

// startTLSSite starts a TLS 1.3 server with HTTP/2.
func startTLSSite(t testing.TB, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// startLink starts a TLS server that echoes everything. It stands in for the
// ORPort: the tunnel carries a TLS connection to it, as Tor's link is TLS.
func startLink(t testing.TB) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "link.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"link.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

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
	return ln.Addr().String()
}

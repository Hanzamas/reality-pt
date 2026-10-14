// Package lab builds small local copies of the real setup so that tests can
// measure the traffic a censor would see. It stands up a REALITY bridge in
// front of a TLS 1.3 cover site, with a TLS server behind it that plays the
// part of Tor's link, and an ordinary HTTP/2 site to compare against.
package lab

import (
	"bytes"
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
	"strconv"
	"testing"
	"time"

	"github.com/hanzamas/reality-pt/internal/pt/relay"
	"github.com/hanzamas/reality-pt/internal/measure/traffic"
	"github.com/hanzamas/reality-pt/transport/reality"
)

const (
	// SNI is the server name of the cover site.
	SNI = "cover.test"
	// CellLen is the size of a Tor cell.
	CellLen = 514

	timeout = 30 * time.Second
)

// Placement says which loopback addresses the lab listens on. Tests keep
// everything on 127.0.0.1. A packet capture puts each part on its own
// address, because a censor can only tell the client from the server by their
// addresses.
type Placement struct {
	// Bridge is where the bridge listens.
	Bridge string
	// Side is where the cover site and the link behind the bridge listen.
	Side string
}

// Local puts every part on 127.0.0.1.
var Local = Placement{Bridge: "127.0.0.1", Side: "127.0.0.1"}

// Bridge is a running REALITY server with a Tor-like link behind it.
type Bridge struct {
	// Addr is where clients connect.
	Addr string
	// Params are the client parameters for this bridge, shaper included.
	Params reality.ClientParams
}

// StartBridge starts a bridge on 127.0.0.1 that uses the named shaper.
func StartBridge(t testing.TB, shaperName string) *Bridge {
	t.Helper()
	return StartBridgeAt(t, Local, shaperName)
}

// StartBridgeAt starts a bridge at the given placement.
func StartBridgeAt(t testing.TB, p Placement, shaperName string) *Bridge {
	t.Helper()

	cover := StartSite(t, p.Side)
	link := startLink(t, p.Side)

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
	inner, err := net.Listen("tcp", net.JoinHostPort(p.Bridge, "0"))
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
	b.session(t, tap.Addr, rng)
	return traffic.AfterHandshake(tap.Wait(timeout))
}

// TorLikeTraffic is TorLikeSession without the tap, for packet captures.
func (b *Bridge) TorLikeTraffic(t testing.TB, rng *mrand.Rand) {
	t.Helper()
	b.session(t, b.Addr, rng)
}

func (b *Bridge) session(t testing.TB, addr string, rng *mrand.Rand) {
	t.Helper()
	client, err := reality.NewClient(b.Params)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.DialTimeout("tcp", addr, timeout)
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
	for cells := 40 + rng.IntN(40); cells > 0; {
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
}

// Browsing is an ordinary HTTP/2 site and a way to visit it.
type Browsing struct {
	server *httptest.Server
}

// StartBrowsing starts a TLS 1.3 HTTP/2 site on 127.0.0.1 that answers with a
// body of the size asked for in the "n" query parameter.
func StartBrowsing(t testing.TB) *Browsing { return StartBrowsingAt(t, "127.0.0.1") }

// StartBrowsingAt starts the site on the given address.
func StartBrowsingAt(t testing.TB, ip string) *Browsing {
	t.Helper()
	return &Browsing{server: startTLSSite(t, ip, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		_, _ = w.Write(make([]byte, min(max(n, 0), 1<<20)))
		_, _ = io.Copy(io.Discard, r.Body)
	}))}
}

// Addr is where the site listens.
func (b *Browsing) Addr() string { return b.server.Listener.Addr().String() }

// Visit visits the site through a tap and returns the application data records
// the tap saw after the handshake.
func (b *Browsing) Visit(t testing.TB, rng *mrand.Rand) []traffic.Step {
	t.Helper()
	tap := traffic.StartTap(t, b.Addr())
	b.visit(t, tap.Addr, rng)
	return traffic.AfterHandshake(tap.Wait(timeout))
}

// VisitDirect is Visit without the tap, for packet captures.
func (b *Browsing) VisitDirect(t testing.TB, rng *mrand.Rand) {
	t.Helper()
	b.visit(t, b.Addr(), rng)
}

// visit does one of four kinds of visit, so the comparison traffic is not only
// page loads: chatty exchanges of small messages look much like Tor cells.
func (b *Browsing) visit(t testing.TB, addr string, rng *mrand.Rand) {
	t.Helper()
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   &tls.Config{ServerName: SNI, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
	get := func(size int) {
		url := "https://" + SNI + "/page?n=" + strconv.Itoa(size)
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	post := func(size int) {
		resp, err := client.Post("https://"+SNI+"/upload?n=200", "application/octet-stream", bytes.NewReader(make([]byte, size)))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	switch rng.IntN(4) {
	case 0: // browsing: sizes from 400 bytes to 300 KB, even on a log scale
		for requests := 3 + rng.IntN(6); requests > 0; requests-- {
			get(int(400 * math.Exp(rng.Float64()*math.Log(300_000.0/400))))
		}
	case 1: // polling: many small requests and replies
		for requests := 15 + rng.IntN(30); requests > 0; requests-- {
			if rng.IntN(3) == 0 {
				post(100 + rng.IntN(500))
			} else {
				get(200 + rng.IntN(600))
			}
			time.Sleep(time.Duration(rng.IntN(3)) * time.Millisecond)
		}
	case 2: // download
		for requests := 1 + rng.IntN(2); requests > 0; requests-- {
			get(200_000 + rng.IntN(800_000))
		}
	default: // upload
		post(50_000 + rng.IntN(350_000))
		get(300)
	}
	client.CloseIdleConnections()
}

// StartSite starts a TLS 1.3 HTTP/2 site that answers every request with a
// short body.
func StartSite(t testing.TB, ip string) *httptest.Server {
	t.Helper()
	return startTLSSite(t, ip, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "cover site")
	}))
}

// startTLSSite starts a TLS 1.3 server with HTTP/2 on the given address.
func startTLSSite(t testing.TB, ip string, h http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener.Close()
	srv.Listener = ln
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// startLink starts a TLS server that echoes everything. It stands in for the
// ORPort: the tunnel carries a TLS connection to it, as Tor's link is TLS.
func startLink(t testing.TB, ip string) string {
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
	ln, err := tls.Listen("tcp", net.JoinHostPort(ip, "0"), &tls.Config{
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

// StartEcho starts a TCP server on ip that echoes everything it receives and
// returns its address. It plays a server for protocols that are not TLS.
func StartEcho(t testing.TB, ip string) string {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
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

// RandomTraffic sends random bytes to an echo server and reads them back, the
// way a fully encrypted protocol that has no handshake of its own would.
func RandomTraffic(t testing.TB, addr string, rng *mrand.Rand) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	payload := make([]byte, 1000+rng.IntN(1000))
	for i := range payload {
		payload[i] = byte(rng.IntN(256))
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write random bytes: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, len(payload))); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
}

// TLSWithName opens a TLS connection to addr that asks for the given server
// name, and does a short HTTP/2 exchange.
func TLSWithName(t testing.TB, addr, serverName string) {
	t.Helper()
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   &tls.Config{ServerName: serverName, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
	resp, err := client.Get("https://" + serverName + "/")
	if err != nil {
		t.Fatalf("GET with server name %s: %v", serverName, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	client.CloseIdleConnections()
}

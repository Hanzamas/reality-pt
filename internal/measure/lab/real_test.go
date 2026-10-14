package lab

import (
	"context"
	"crypto/tls"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hanzamas/reality-pt/internal/measure/traffic"
)

// realSites are public sites that answer over TLS 1.3 and HTTP/2. The traces
// keep only sizes and directions.
var realSites = []string{
	"www.wikipedia.org", "www.cloudflare.com", "github.com", "www.mozilla.org",
	"www.microsoft.com", "www.apple.com", "www.python.org", "go.dev",
	"www.debian.org", "www.kernel.org", "news.ycombinator.com", "www.bbc.com",
	"www.nytimes.com", "stackoverflow.com", "www.reddit.com", "www.amazon.com",
	"www.fastly.com", "www.akamai.com", "duckduckgo.com", "www.theguardian.com",
}

const (
	// savedSteps is how much of the start of each connection is kept.
	savedSteps = 40
	// visitsPerSite is how many times each site is visited.
	visitsPerSite = 8
)

// TestCollectRealTraces visits real sites and writes the start of each
// connection to the file named by REALITY_PT_TRACE_OUT. It needs the internet
// and only runs when that variable is set. The traces are the comparison
// traffic for the detectors, and the source of the shaper's opening profiles.
func TestCollectRealTraces(t *testing.T) {
	out := os.Getenv("REALITY_PT_TRACE_OUT")
	if out == "" {
		t.Skip("set REALITY_PT_TRACE_OUT to collect traces from real sites")
	}
	rng := rand.New(rand.NewPCG(5, 6))

	var file traffic.SavedFile
	file.Note = "Sizes and directions of the first application data records after the TLS 1.3 handshake of HTTP/2 visits, collected from a GitHub-hosted runner."
	for _, site := range realSites {
		got := 0
		for visit := 0; visit < visitsPerSite; visit++ {
			steps, ok := visitReal(t, site, rng)
			if !ok {
				continue
			}
			file.Traces = append(file.Traces, traffic.NewSavedTrace(site, steps, savedSteps))
			got++
		}
		t.Logf("%-28s %d traces", site, got)
	}
	if len(file.Traces) < 50 {
		t.Fatalf("only %d traces collected", len(file.Traces))
	}
	if err := traffic.WriteSaved(out, file); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d traces to %s", len(file.Traces), out)
}

// visitReal loads a site over HTTP/2 and returns the start of the first
// connection. ok is false if the connection was not TLS 1.3 with HTTP/2 or the
// visit failed, since a site that is down is not a reason to fail.
func visitReal(t *testing.T, site string, rng *rand.Rand) (steps []traffic.Step, ok bool) {
	t.Helper()

	var (
		mu     sync.Mutex
		first  *traffic.Trace
		usable = true
	)
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				recorded, trace := traffic.Observe(raw)
				host, _, _ := net.SplitHostPort(addr)
				conn := tls.Client(recorded, &tls.Config{ServerName: host, NextProtos: []string{"h2", "http/1.1"}})
				if err := conn.HandshakeContext(ctx); err != nil {
					_ = raw.Close()
					return nil, err
				}
				mu.Lock()
				defer mu.Unlock()
				if first == nil {
					first = trace
					state := conn.ConnectionState()
					usable = state.Version == tls.VersionTLS13 && state.NegotiatedProtocol == "h2"
				}
				return conn, nil
			},
		},
	}

	for _, path := range []string{"/", "/favicon.ico"} {
		resp, err := client.Get("https://" + site + path)
		if err != nil {
			return nil, false
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2<<20))
		_ = resp.Body.Close()
		time.Sleep(time.Duration(50+rng.IntN(250)) * time.Millisecond)
	}
	client.CloseIdleConnections()
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if first == nil || !usable {
		return nil, false
	}
	steps = traffic.AfterHandshake(first.Records())
	return steps, len(steps) >= 10
}

// Package e2e runs the real client and server binaries the way Tor does: it
// sets the TOR_PT_* environment, reads the PT protocol from stdout, and talks
// to the client over SOCKS5 with the bridge line arguments in the username.
// An echo server stands in for the bridge's ORPort.
package e2e_test

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hanzamas/reality-pt/transport/reality"
)

const (
	coverSNI = "cover.test"
	timeout  = 60 * time.Second
)

// binDir holds the binaries built by TestMain.
var binDir string

// exe returns the file name of an executable on this platform.
func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func TestMain(m *testing.M) { os.Exit(run(m)) }

func run(m *testing.M) int {
	dir, err := os.MkdirTemp("", "reality-pt-e2e")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	binDir = dir

	for _, name := range []string{"reality-client", "reality-server"} {
		cmd := exec.Command("go", "build", "-o", filepath.Join(dir, exe(name)), "../cmd/"+name)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n", name, err)
			return 1
		}
	}
	return m.Run()
}

func TestTunnelThroughPTBinaries(t *testing.T) {
	c := startChain(t)

	conn, code := socksConnect(t, c.socksAddr, c.username(nil), c.bridgeAddr)
	if code != 0 {
		t.Fatalf("SOCKS reply code = %d, want 0", code)
	}

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

func TestClientRejectsAWrongKey(t *testing.T) {
	c := startChain(t)

	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	username := c.username(map[string]string{"public-key": reality.EncodeKey(other.PublicKey().Bytes())})

	if _, code := socksConnect(t, c.socksAddr, username, c.bridgeAddr); code == 0 {
		t.Fatal("SOCKS request with a wrong public key was granted")
	}
}

func TestClientRejectsMissingArguments(t *testing.T) {
	c := startChain(t)

	if _, code := socksConnect(t, c.socksAddr, "unrelated=value", c.bridgeAddr); code == 0 {
		t.Fatal("SOCKS request without bridge arguments was granted")
	}
}

// chain is a running client and server plus what a Tor client would know
// about the bridge.
type chain struct {
	socksAddr  string
	bridgeAddr string
	args       map[string]string
}

// username encodes the bridge line arguments as Tor does in the SOCKS
// username, with overrides applied.
func (c chain) username(override map[string]string) string {
	args := make(map[string]string, len(c.args))
	for k, v := range c.args {
		args[k] = v
	}
	for k, v := range override {
		args[k] = v
	}
	pairs := make([]string, 0, len(args))
	for k, v := range args {
		pairs = append(pairs, k+"="+v)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ";")
}

func startChain(t *testing.T) chain {
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
	shortID := reality.ShortID{0xab, 0xcd, 1, 2, 3, 4, 5, 6}
	options := strings.Join([]string{
		"reality:private-key=" + reality.EncodeKey(priv.Bytes()),
		"reality:dest=" + strings.ReplaceAll(cover.Listener.Addr().String(), ":", `\:`),
		"reality:server-names=" + coverSNI,
		"reality:short-ids=" + shortID.String(),
	}, ";")

	server := startPT(t, "reality-server",
		"TOR_PT_MANAGED_TRANSPORT_VER=1",
		"TOR_PT_STATE_LOCATION="+t.TempDir(),
		"TOR_PT_SERVER_TRANSPORTS=reality",
		"TOR_PT_SERVER_BINDADDR=reality-"+freeAddr(t),
		"TOR_PT_ORPORT="+startEcho(t),
		"TOR_PT_SERVER_TRANSPORT_OPTIONS="+options,
	)
	smethod := waitLine(t, server, "SMETHOD ")
	waitLine(t, server, "SMETHODS DONE")
	bridgeAddr, args := parseSmethod(t, smethod)

	client := startPT(t, "reality-client",
		"TOR_PT_MANAGED_TRANSPORT_VER=1",
		"TOR_PT_STATE_LOCATION="+t.TempDir(),
		"TOR_PT_CLIENT_TRANSPORTS=reality",
	)
	cmethod := strings.Fields(waitLine(t, client, "CMETHOD "))
	waitLine(t, client, "CMETHODS DONE")
	if len(cmethod) < 4 {
		t.Fatalf("unexpected CMETHOD line: %q", cmethod)
	}
	return chain{socksAddr: cmethod[3], bridgeAddr: bridgeAddr, args: args}
}

// parseSmethod reads "SMETHOD <name> <addr> ARGS:k=v,k=v".
func parseSmethod(t *testing.T, line string) (addr string, args map[string]string) {
	t.Helper()
	fields := strings.Fields(line)
	if len(fields) < 4 || !strings.HasPrefix(fields[3], "ARGS:") {
		t.Fatalf("unexpected SMETHOD line: %q", line)
	}
	args = make(map[string]string)
	for _, kv := range strings.Split(strings.TrimPrefix(fields[3], "ARGS:"), ",") {
		k, v, _ := strings.Cut(kv, "=")
		args[k] = v
	}
	return fields[2], args
}

// startPT runs one of the built binaries and returns its stdout lines.
func startPT(t *testing.T, name string, env ...string) <-chan string {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, filepath.Join(binDir, exe(name)))
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = logWriter{t: t, prefix: name + ": "}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	lines := make(chan string, 1024)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	return lines
}

// waitLine returns the first line with the given prefix and fails on a PT
// error line or a timeout.
func waitLine(t *testing.T, lines <-chan string, prefix string) string {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatalf("process exited before printing %q", prefix)
			}
			t.Log(l)
			if strings.Contains(l, "ERROR") {
				t.Fatalf("PT reported an error: %s", l)
			}
			if strings.HasPrefix(l, prefix) {
				return l
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q", prefix)
		}
	}
}

// socksConnect performs a SOCKS5 CONNECT with username/password
// authentication and returns the connection and the reply code.
func socksConnect(t *testing.T, socksAddr, username, target string) (net.Conn, byte) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", socksAddr, timeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(timeout))

	exchange(t, conn, []byte{5, 1, 2}, 2) // offer username/password

	auth := append([]byte{1, byte(len(username))}, username...)
	auth = append(auth, 1, 0) // password: a single NUL, as Tor sends it
	exchange(t, conn, auth, 2)

	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("target %q is not an IPv4 address", target)
	}
	request := append([]byte{5, 1, 0, 1}, ip...)
	request = append(request, byte(port>>8), byte(port))
	reply := exchange(t, conn, request, 10)
	return conn, reply[1]
}

// exchange writes req and reads exactly n reply bytes.
func exchange(t *testing.T, conn net.Conn, req []byte, n int) []byte {
	t.Helper()
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, n)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read: %v", err)
	}
	return reply
}

// startEcho stands in for the bridge's ORPort.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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

// freeAddr returns a loopback address that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// logWriter forwards a process's stderr to the test log.
type logWriter struct {
	t      *testing.T
	prefix string
}

func (w logWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s%s", w.prefix, strings.TrimRight(string(p), "\r\n"))
	return len(p), nil
}

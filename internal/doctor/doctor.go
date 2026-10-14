// Package doctor checks whether a site makes a good cover for a bridge. The
// REALITY server copies the cover's handshake, so the cover must speak TLS 1.3
// with a key exchange the server can mimic, and it should sit close to the
// bridge on the network.
package doctor

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Status is the outcome of one check.
type Status int

const (
	// Pass means the check found nothing wrong.
	Pass Status = iota
	// Warn means the cover works but the operator should look.
	Warn
	// Fail means the site cannot serve as a cover.
	Fail
)

func (s Status) String() string {
	switch s {
	case Pass:
		return "ok"
	case Warn:
		return "warn"
	default:
		return "FAIL"
	}
}

// Check is one finding.
type Check struct {
	Name   string
	Status Status
	Detail string
}

// Report is the list of findings, in the order they ran.
type Report []Check

// OK reports whether no check failed.
func (r Report) OK() bool {
	for _, c := range r {
		if c.Status == Fail {
			return false
		}
	}
	return true
}

// Options selects what to check.
type Options struct {
	// Dest is the cover site as host:port.
	Dest string
	// ServerName is the SNI to use. It defaults to the host of Dest.
	ServerName string
	// BridgeIP, if set, is compared with the cover's addresses by network.
	BridgeIP net.IP
	// RootCAs verifies the cover's certificate. Nil means the system roots.
	RootCAs *x509.CertPool
	// Resolver looks up TXT records for the network comparison. Nil means the
	// system resolver.
	Resolver TXTResolver
	// Timeout bounds each network step. Zero means ten seconds.
	Timeout time.Duration
}

// Run checks the cover site and returns what it found.
func Run(ctx context.Context, opts Options) Report {
	host, _, err := net.SplitHostPort(opts.Dest)
	if err != nil {
		return Report{{"destination", Fail, "must be host:port: " + err.Error()}}
	}
	if opts.ServerName == "" {
		opts.ServerName = host
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	var report Report
	state, conn, ok := handshake(ctx, opts, &report)
	if !ok {
		return report
	}
	defer conn.Close()

	report = append(report, checkVersion(state), checkKeyShare(conn), checkALPN(state), checkCertificate(state, opts))
	if opts.BridgeIP != nil {
		report = append(report, checkNetwork(ctx, opts, host))
	}
	return report
}

// handshake connects with a Chrome-shaped ClientHello, the way a client
// reaches the bridge.
func handshake(ctx context.Context, opts Options, report *Report) (utls.ConnectionState, *utls.UConn, bool) {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", opts.Dest)
	if err != nil {
		*report = append(*report, Check{"connect", Fail, err.Error()})
		return utls.ConnectionState{}, nil, false
	}
	*report = append(*report, Check{"connect", Pass, "reached " + raw.RemoteAddr().String()})

	conn := utls.UClient(raw, &utls.Config{
		ServerName: opts.ServerName,
		// The certificate is checked separately so a bad one is a warning,
		// not a failed connection.
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		*report = append(*report, Check{"tls handshake", Fail, err.Error()})
		return utls.ConnectionState{}, nil, false
	}
	return conn.ConnectionState(), conn, true
}

func checkVersion(state utls.ConnectionState) Check {
	if state.Version != utls.VersionTLS13 {
		return Check{"tls 1.3", Fail, fmt.Sprintf("the site negotiated protocol version 0x%04x, REALITY needs TLS 1.3", state.Version)}
	}
	return Check{"tls 1.3", Pass, "negotiated TLS 1.3"}
}

// checkKeyShare looks at the group the site picked. The REALITY server only
// accepts a cover whose ServerHello carries an X25519 or X25519MLKEM768 share.
func checkKeyShare(conn *utls.UConn) Check {
	hello := conn.HandshakeState.ServerHello
	if hello == nil {
		return Check{"key exchange", Warn, "the server hello is not available"}
	}
	switch group := hello.ServerShare.Group; group {
	case utls.X25519:
		return Check{"key exchange", Pass, "the site chose X25519"}
	case utls.X25519MLKEM768:
		return Check{"key exchange", Pass, "the site chose X25519MLKEM768"}
	default:
		return Check{"key exchange", Fail, fmt.Sprintf("the site chose group %d, the bridge can only copy X25519 or X25519MLKEM768", uint16(group))}
	}
}

func checkALPN(state utls.ConnectionState) Check {
	if state.NegotiatedProtocol == "h2" {
		return Check{"http/2", Pass, "the site speaks h2, like most browsers expect"}
	}
	return Check{"http/2", Warn, fmt.Sprintf("the site negotiated %q, not h2", state.NegotiatedProtocol)}
}

func checkCertificate(state utls.ConnectionState, opts Options) Check {
	if len(state.PeerCertificates) == 0 {
		return Check{"certificate", Fail, "the site sent no certificate"}
	}
	verify := x509.VerifyOptions{
		DNSName:       opts.ServerName,
		Roots:         opts.RootCAs,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range state.PeerCertificates[1:] {
		verify.Intermediates.AddCert(cert)
	}
	if _, err := state.PeerCertificates[0].Verify(verify); err != nil {
		return Check{"certificate", Warn, "the certificate does not verify for " + opts.ServerName + ": " + err.Error()}
	}
	return Check{"certificate", Pass, fmt.Sprintf("valid for %s, chain of %d", opts.ServerName, len(state.PeerCertificates))}
}

// checkNetwork compares the network that originates the bridge address with
// the networks of the cover's addresses. A bridge that claims to be a site
// hosted elsewhere stands out to a censor that looks at both.
func checkNetwork(ctx context.Context, opts Options, host string) Check {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	bridgeASN, err := originASN(ctx, resolver, opts.BridgeIP)
	if err != nil {
		return Check{"network", Warn, "could not look up the bridge's network: " + err.Error()}
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return Check{"network", Warn, "could not resolve the cover: " + err.Error()}
	}
	var coverASNs []string
	for _, a := range addrs {
		asn, err := originASN(ctx, resolver, a.IP)
		if err != nil {
			continue
		}
		if asn == bridgeASN {
			return Check{"network", Pass, "the bridge and the cover are both in AS" + asn}
		}
		coverASNs = append(coverASNs, "AS"+asn)
	}
	if len(coverASNs) == 0 {
		return Check{"network", Warn, "could not look up the cover's network"}
	}
	return Check{"network", Warn, fmt.Sprintf("the bridge is in AS%s but the cover is in %s: a cover on the bridge's own network blends in better", bridgeASN, strings.Join(coverASNs, ", "))}
}

// TXTResolver looks up TXT records.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// originASN asks Team Cymru's DNS service which AS originates ip.
func originASN(ctx context.Context, r TXTResolver, ip net.IP) (string, error) {
	name, err := cymruName(ip)
	if err != nil {
		return "", err
	}
	records, err := r.LookupTXT(ctx, name)
	if err != nil {
		return "", err
	}
	for _, record := range records {
		// "13335 | 1.1.1.0/24 | US | arin | 2010-07-14"
		if asn, _, ok := strings.Cut(record, "|"); ok {
			// A prefix announced by several ASes lists them separated by spaces.
			if fields := strings.Fields(asn); len(fields) > 0 {
				return fields[0], nil
			}
		}
	}
	return "", errors.New("no origin record")
}

// cymruName builds the query name for the Team Cymru IP-to-ASN service.
func cymruName(ip net.IP) (string, error) {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0]), nil
	}
	v6 := ip.To16()
	if v6 == nil {
		return "", fmt.Errorf("not an IP address: %v", ip)
	}
	var b strings.Builder
	for i := len(v6) - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "%x.%x.", v6[i]&0x0f, v6[i]>>4)
	}
	b.WriteString("origin6.asn.cymru.com")
	return b.String(), nil
}

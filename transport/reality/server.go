package reality

import (
	"net"
	"time"

	xr "github.com/xtls/reality"

	"github.com/hanzamas/reality-pt/transport"
)

// coverDialTimeout bounds how long the bridge waits to reach the cover site.
const coverDialTimeout = 10 * time.Second

// Server is the bridge side of the transport.
type Server struct {
	params ServerParams
	replay *seenCache
}

var _ transport.ServerStage = (*Server)(nil)

// NewServer returns a Server for the given parameters.
func NewServer(p ServerParams) *Server {
	return &Server{params: p, replay: newReplayCache(p.MaxTimeDiff)}
}

// NewServerStage is the transport.ServerFactory for REALITY.
func NewServerStage(args transport.Args) (transport.ServerStage, error) {
	p, err := ParseServerParams(args)
	if err != nil {
		return nil, err
	}
	return NewServer(p), nil
}

// Listen implements transport.ServerStage. inner must accept TCP connections.
// Clients that authenticate come out of Accept. Everything else is forwarded
// to the cover site inside the library and never reaches the caller. A
// ClientHello that was seen before counts as a stranger even if its token is
// valid.
func (s *Server) Listen(inner net.Listener) net.Listener {
	return xr.NewListener(&replayListener{Listener: inner, cache: s.replay}, s.config())
}

// PublicArgs implements transport.ServerStage.
func (s *Server) PublicArgs() map[string][]string { return s.params.PublicArgs() }

func (s *Server) config() *xr.Config {
	p := s.params
	limit := xr.LimitFallback{
		AfterBytes:       p.FallbackLimit.AfterBytes,
		BytesPerSec:      p.FallbackLimit.BytesPerSec,
		BurstBytesPerSec: p.FallbackLimit.BurstBytesPerSec,
	}
	cfg := &xr.Config{
		DialContext: (&net.Dialer{Timeout: coverDialTimeout}).DialContext,

		Type: "tcp",
		Dest: p.Dest,
		Xver: p.ProxyProtocol,

		ServerNames: make(map[string]bool, len(p.ServerNames)),
		PrivateKey:  p.PrivateKey,
		MaxTimeDiff: p.MaxTimeDiff,
		ShortIds:    make(map[[8]byte]bool, len(p.ShortIDs)),

		LimitFallbackUpload:   limit,
		LimitFallbackDownload: limit,

		SessionTicketsDisabled: true,
	}
	if p.MinClientVersion != nil {
		cfg.MinClientVer = p.MinClientVersion[:]
	}
	if p.MaxClientVersion != nil {
		cfg.MaxClientVer = p.MaxClientVersion[:]
	}
	for _, name := range p.ServerNames {
		cfg.ServerNames[name] = true
	}
	for _, id := range p.ShortIDs {
		cfg.ShortIds[id] = true
	}
	return cfg
}

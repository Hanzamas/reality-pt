// Package ptclient runs the client half of a managed pluggable transport: it
// listens for SOCKS requests from Tor and, for each one, runs the pipeline
// dial, handshake, shape, relay.
package ptclient

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"

	"github.com/hanzamas/reality-pt/internal/ptrun"
	"github.com/hanzamas/reality-pt/internal/relay"
	"github.com/hanzamas/reality-pt/shaper"
	"github.com/hanzamas/reality-pt/transport"
)

// connectTimeout bounds the TCP dial and the transport handshake together.
const connectTimeout = 30 * time.Second

// Config describes one transport to serve.
type Config struct {
	// Name is the transport name Tor asks for.
	Name string
	// Version is reported to Tor.
	Version string
	// Factory builds the handshake stage for each bridge line.
	Factory transport.ClientFactory
	// Shaper wraps every tunnel connection.
	Shaper shaper.Shaper
	Log    *slog.Logger
}

// Run serves SOCKS requests until ctx ends.
func Run(ctx context.Context, cfg Config) error {
	info, err := pt.ClientSetup(nil)
	if err != nil {
		return err
	}
	if info.ProxyURL != nil {
		_ = pt.ProxyError("proxy is not supported")
		return errors.New("an upstream proxy is not supported")
	}
	pt.ReportVersion(cfg.Name, cfg.Version)

	c := &client{cfg: cfg}
	var (
		listeners []*pt.SocksListener
		wg        sync.WaitGroup
	)
	for _, name := range info.MethodNames {
		if name != cfg.Name {
			_ = pt.CmethodError(name, "no such method")
			continue
		}
		ln, err := pt.ListenSocks("tcp", "127.0.0.1:0")
		if err != nil {
			_ = pt.CmethodError(name, err.Error())
			continue
		}
		pt.Cmethod(name, ln.Version(), ln.Addr())
		cfg.Log.Info("listening for SOCKS", "transport", name, "addr", ln.Addr().String())
		listeners = append(listeners, ln)
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.acceptLoop(ctx, ln)
		}()
	}
	pt.CmethodsDone()
	if len(listeners) == 0 {
		return errors.New("no transport could be started")
	}

	<-ctx.Done()
	for _, ln := range listeners {
		_ = ln.Close()
	}
	wg.Wait()
	return nil
}

type client struct {
	cfg    Config
	dialer net.Dialer
}

func (c *client) acceptLoop(ctx context.Context, ln *pt.SocksListener) {
	var (
		wg      sync.WaitGroup
		backoff ptrun.Backoff
	)
	defer wg.Wait()
	for {
		conn, err := ln.AcceptSocks()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			c.cfg.Log.Warn("SOCKS accept failed", "err", err)
			if !backoff.Wait(ctx) {
				return
			}
			continue
		}
		backoff.Reset()
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.serve(ctx, conn)
		}()
	}
}

// serve runs the pipeline for one SOCKS request.
func (c *client) serve(ctx context.Context, sc *pt.SocksConn) {
	defer sc.Close()

	tunnel, err := c.connect(ctx, sc.Req)
	if err != nil {
		c.cfg.Log.Warn("bridge connection failed", "err", err)
		_ = sc.Reject()
		return
	}
	defer tunnel.Close()

	if err := sc.Grant(nil); err != nil {
		c.cfg.Log.Warn("SOCKS grant failed", "err", err)
		return
	}
	stop := context.AfterFunc(ctx, func() {
		_ = tunnel.Close()
		_ = sc.Close()
	})
	defer stop()

	relay.Pipe(sc, tunnel)
}

// connect runs the pipeline stages up to the tunnel: dial, handshake, shape.
func (c *client) connect(ctx context.Context, req pt.SocksRequest) (net.Conn, error) {
	stage, err := c.cfg.Factory(req.Args)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	raw, err := c.dialer.DialContext(ctx, "tcp", req.Target)
	if err != nil {
		return nil, err
	}
	tunnel, err := stage.Handshake(ctx, raw)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c.cfg.Shaper.Wrap(tunnel), nil
}

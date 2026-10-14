// Package ptserver runs the bridge half of a managed pluggable transport: it
// accepts tunnel connections and, for each one, runs the pipeline shape,
// connect to the ORPort, relay.
package ptserver

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"

	"github.com/hanzamas/reality-pt/internal/ptrun"
	"github.com/hanzamas/reality-pt/internal/relay"
	"github.com/hanzamas/reality-pt/shaper"
	"github.com/hanzamas/reality-pt/transport"
)

// Config describes one transport to serve.
type Config struct {
	// Name is the transport name Tor asks for.
	Name string
	// Version is reported to Tor.
	Version string
	// Factory builds the server stage from the transport options in torrc.
	Factory transport.ServerFactory
	// Shaper wraps every tunnel connection.
	Shaper shaper.Shaper
	Log    *slog.Logger
}

// Run serves tunnel connections until ctx ends.
func Run(ctx context.Context, cfg Config) error {
	info, err := pt.ServerSetup(nil)
	if err != nil {
		return err
	}
	pt.ReportVersion(cfg.Name, cfg.Version)

	s := &server{cfg: cfg, info: info}
	var (
		listeners []net.Listener
		wg        sync.WaitGroup
	)
	for _, b := range info.Bindaddrs {
		if b.MethodName != cfg.Name {
			_ = pt.SmethodError(b.MethodName, "no such method")
			continue
		}
		ln, err := s.listen(b)
		if err != nil {
			_ = pt.SmethodError(b.MethodName, err.Error())
			continue
		}
		cfg.Log.Info("accepting tunnel connections", "transport", b.MethodName)
		listeners = append(listeners, ln)
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.acceptLoop(ctx, ln)
		}()
	}
	pt.SmethodsDone()
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

type server struct {
	cfg  Config
	info pt.ServerInfo
}

// listen builds the server stage for one bind address and announces it to Tor
// together with the public arguments that go into the bridge line.
func (s *server) listen(b pt.Bindaddr) (net.Listener, error) {
	stage, err := s.cfg.Factory(b.Options)
	if err != nil {
		return nil, err
	}
	tcp, err := net.ListenTCP("tcp", b.Addr)
	if err != nil {
		return nil, err
	}
	args := stage.PublicArgs()
	pt.SmethodArgs(b.MethodName, tcp.Addr(), pt.Args(args))
	s.saveBridgeLine(b.MethodName, tcp.Addr(), args)
	return stage.Listen(tcp), nil
}

// saveBridgeLine writes the bridge line for the operator. It is a courtesy, so
// a failure is logged and does not stop the bridge.
func (s *server) saveBridgeLine(name string, listen net.Addr, args map[string][]string) {
	dir, err := pt.MakeStateDir()
	if err != nil {
		s.cfg.Log.Warn("no state directory, bridge line not saved", "err", err)
		return
	}
	if err := writeBridgeLine(dir, name, bridgeLine(name, listen, args)); err != nil {
		s.cfg.Log.Warn("bridge line not saved", "err", err)
	}
}

func (s *server) acceptLoop(ctx context.Context, ln net.Listener) {
	var (
		wg      sync.WaitGroup
		backoff ptrun.Backoff
	)
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			s.cfg.Log.Warn("accept failed", "err", err)
			if !backoff.Wait(ctx) {
				return
			}
			continue
		}
		backoff.Reset()
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.serve(ctx, conn)
		}()
	}
}

// serve runs the pipeline for one tunnel connection. It does not log client
// addresses: a bridge should not keep them.
func (s *server) serve(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	or, err := pt.DialOr(&s.info, conn.RemoteAddr().String(), s.cfg.Name)
	if err != nil {
		s.cfg.Log.Warn("ORPort connection failed", "err", err)
		return
	}
	defer or.Close()

	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		_ = or.Close()
	})
	defer stop()

	relay.Pipe(s.cfg.Shaper.Wrap(conn), or)
}

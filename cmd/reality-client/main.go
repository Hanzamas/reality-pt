// Command reality-client is the Tor pluggable transport client.
package main

import (
	"log/slog"
	"os"

	"github.com/hanzamas/reality-pt/internal/ptclient"
	"github.com/hanzamas/reality-pt/internal/ptrun"
	"github.com/hanzamas/reality-pt/internal/version"
	"github.com/hanzamas/reality-pt/shaper"
	"github.com/hanzamas/reality-pt/transport/reality"
)

func main() { os.Exit(run()) }

func run() int {
	// stdout belongs to the PT protocol, so logs go to stderr.
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctx, stop := ptrun.Context()
	defer stop()

	err := ptclient.Run(ctx, ptclient.Config{
		Name:    reality.Name,
		Version: version.Version,
		Factory: reality.NewClientStage,
		Shaper:  shaper.Noop{},
		Log:     log,
	})
	if err != nil {
		log.Error("reality-client stopped", "err", err)
		return 1
	}
	return 0
}

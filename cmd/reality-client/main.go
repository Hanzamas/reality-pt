// Command reality-client is the Tor pluggable transport client.
package main

import (
	"log/slog"
	"os"

	"github.com/hanzamas/reality-pt/internal/pt/client"
	"github.com/hanzamas/reality-pt/internal/pt/lifecycle"
	"github.com/hanzamas/reality-pt/internal/version"
	"github.com/hanzamas/reality-pt/transport/reality"
)

func main() { os.Exit(run()) }

func run() int {
	// stdout belongs to the PT protocol, so logs go to stderr.
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctx, stop := lifecycle.Context()
	defer stop()

	err := client.Run(ctx, client.Config{
		Name:    reality.Name,
		Version: version.Version,
		Factory: reality.NewClientStage,
		Log:     log,
	})
	if err != nil {
		log.Error("reality-client stopped", "err", err)
		return 1
	}
	return 0
}

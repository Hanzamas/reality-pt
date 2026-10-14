// Command reality-check tests whether a site makes a good cover for a bridge.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/hanzamas/reality-pt/internal/doctor"
)

func main() { os.Exit(run()) }

func run() int {
	dest := flag.String("dest", "", "cover site as host:port, for example www.microsoft.com:443")
	serverName := flag.String("sni", "", "server name to use (default: the host of -dest)")
	bridgeIP := flag.String("bridge-ip", "", "public address of the bridge, to compare networks")
	flag.Parse()

	if *dest == "" {
		fmt.Fprintln(os.Stderr, "reality-check: -dest is required")
		flag.Usage()
		return 2
	}
	opts := doctor.Options{Dest: *dest, ServerName: *serverName}
	if *bridgeIP != "" {
		if opts.BridgeIP = net.ParseIP(*bridgeIP); opts.BridgeIP == nil {
			fmt.Fprintf(os.Stderr, "reality-check: %q is not an IP address\n", *bridgeIP)
			return 2
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	report := doctor.Run(ctx, opts)
	for _, c := range report {
		fmt.Printf("[%-4s] %-13s %s\n", c.Status, c.Name, c.Detail)
	}
	if !report.OK() {
		return 1
	}
	return 0
}

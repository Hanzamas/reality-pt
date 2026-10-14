// Package lifecycle holds the process lifecycle shared by the PT client and server.
package lifecycle

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Context returns a context that ends on interrupt or SIGTERM. It also ends
// when stdin closes if Tor set TOR_PT_EXIT_ON_STDIN_CLOSE=1, which is how Tor
// tells a managed transport to quit when it cannot send a signal.
func Context() (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	if os.Getenv("TOR_PT_EXIT_ON_STDIN_CLOSE") == "1" {
		go func() {
			_, _ = io.Copy(io.Discard, os.Stdin)
			stop()
		}()
	}
	return ctx, stop
}

const (
	backoffMin = 5 * time.Millisecond
	backoffMax = time.Second
)

// Backoff paces retries of a failing accept loop. The zero value is ready to
// use.
type Backoff struct {
	delay time.Duration
}

// next advances the delay: 5ms at first, then doubling up to one second.
func (b *Backoff) next() time.Duration {
	if b.delay == 0 {
		b.delay = backoffMin
	} else {
		b.delay = min(2*b.delay, backoffMax)
	}
	return b.delay
}

// Wait sleeps for the next delay. It returns false if ctx ended first.
func (b *Backoff) Wait(ctx context.Context) bool {
	t := time.NewTimer(b.next())
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Reset restarts the delay after a success.
func (b *Backoff) Reset() { b.delay = 0 }

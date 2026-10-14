package lifecycle

import (
	"context"
	"testing"
	"time"
)

func TestBackoffDoublesUpToMax(t *testing.T) {
	var b Backoff
	want := backoffMin
	for range 20 {
		if got := b.next(); got != want {
			t.Fatalf("next() = %v, want %v", got, want)
		}
		want = min(2*want, backoffMax)
	}
	if b.delay != backoffMax {
		t.Fatalf("delay did not reach the cap: %v", b.delay)
	}
	b.Reset()
	if got := b.next(); got != backoffMin {
		t.Fatalf("next() after Reset = %v, want %v", got, backoffMin)
	}
}

func TestBackoffStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := Backoff{delay: backoffMax}
	start := time.Now()
	if b.Wait(ctx) {
		t.Fatal("Wait returned true on a cancelled context")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("Wait did not return promptly after cancel")
	}
}

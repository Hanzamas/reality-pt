package lab

import (
	"math/rand/v2"
	"os"
	"testing"
)

// TestCaptureScenarios generates the traffic that test/censor/run.sh records
// and replays through a censor emulator. It only runs when REALITY_PT_CAPTURE
// is set, because it is pointless without a capture running next to it.
//
// Each scenario gets its own loopback address so the captured packets can be
// told apart, and so a censor can tell the client (127.0.0.1) from a server.
//
//	127.0.0.2  the REALITY bridge, with the padding shaper and a Tor-like link
//	127.0.0.3  an ordinary HTTP/2 site that a browser visits
//	127.0.0.4  a server for random bytes, a stand-in for a fully encrypted protocol
//	127.0.0.5  a site visited with a server name the censor has on its list
//
// The cover site and the link behind the bridge sit on 127.0.0.6.
func TestCaptureScenarios(t *testing.T) {
	if os.Getenv("REALITY_PT_CAPTURE") == "" {
		t.Skip("set REALITY_PT_CAPTURE=1 to generate traffic for a capture")
	}
	const sessions = 6
	rng := rand.New(rand.NewPCG(3, 4))

	bridge := StartBridgeAt(t, Placement{Bridge: "127.0.0.2", Side: "127.0.0.6"}, "padding")
	site := StartBrowsingAt(t, "127.0.0.3")
	echo := StartEcho(t, "127.0.0.4")
	listed := StartSite(t, "127.0.0.5")

	for i := 0; i < sessions; i++ {
		bridge.TorLikeTraffic(t, rng)
		site.VisitDirect(t, rng)
		RandomTraffic(t, echo, rng)
		TLSWithName(t, listed.Listener.Addr().String(), "blocked.example")
	}
}

package lab

import (
	"math/rand/v2"
	"testing"

	"github.com/hanzamas/reality-pt/internal/traffic"
)

const (
	trainSessions = 20
	testSessions  = 20
	benignTrain   = 60
	benignTest    = 40
	firstSteps    = 10
	modalWindow   = 30
	benignFPR     = 0.05
)

func collectTunnel(t *testing.T, shaperName string, n int, rng *rand.Rand) [][]traffic.Step {
	t.Helper()
	b := StartBridge(t, shaperName)
	out := make([][]traffic.Step, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, b.TorLikeSession(t, rng))
	}
	return out
}

func collectBenign(t *testing.T, n int, rng *rand.Rand) [][]traffic.Step {
	t.Helper()
	site := StartBrowsing(t)
	out := make([][]traffic.Step, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, site.Visit(t, rng))
	}
	return out
}

// nearestScores scores each trace by its distance to the closest known trace.
func nearestScores(known, traces [][]traffic.Step) []float64 {
	scores := make([]float64, len(traces))
	for i, tr := range traces {
		scores[i] = traffic.Nearest(known, tr, firstSteps)
	}
	return scores
}

// negModal is minus the share of equal-size records, so that a low value
// means "looks like equal-size units" and FlagRate can be used for both
// detectors.
func negModal(traces [][]traffic.Step) []float64 {
	out := make([]float64, len(traces))
	for i, tr := range traces {
		out[i] = -max(traffic.ModalShare(tr, true, modalWindow), traffic.ModalShare(tr, false, modalWindow))
	}
	return out
}

// TestShapingMovesWhatADetectorSees measures stand-in censors against a
// tunnel without and with the padding shaper. The detectors are made up for
// this project and the browsing traffic is synthetic, so the numbers show
// whether shaping changes what can be seen. They do not predict how a real
// censor reacts.
//
// The experiment has three detectors:
//   - equal-size: the share of records of one size, which fixed-size Tor
//     cells make high and a browser does not.
//   - naive template: the censor knows how an unshaped tunnel starts.
//   - adaptive template: the censor has also seen shaped tunnels and keeps
//     their starts as examples.
func TestShapingMovesWhatADetectorSees(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a few seconds of local traffic")
	}
	rng := rand.New(rand.NewPCG(1, 2))

	plain := collectTunnel(t, "none", trainSessions+testSessions, rng)
	padded := collectTunnel(t, "padding", trainSessions+testSessions, rng)
	benign := collectBenign(t, benignTrain+benignTest, rng)

	plainTrain, plainTest := plain[:trainSessions], plain[trainSessions:]
	paddedTrain, paddedTest := padded[:trainSessions], padded[trainSessions:]
	benignCal, benignTestSet := benign[:benignTrain], benign[benignTrain:]

	// Equal-size detector. A session is flagged when its modal share is above
	// the 95th percentile of the browsing sessions, which is the 5th
	// percentile of the negated values.
	modalTau := traffic.Quantile(negModal(benignCal), benignFPR)
	equal := struct{ plain, padded, benign float64 }{
		plain:  traffic.FlagRate(negModal(plainTest), modalTau),
		padded: traffic.FlagRate(negModal(paddedTest), modalTau),
		benign: traffic.FlagRate(negModal(benignTestSet), modalTau),
	}

	// Naive template detector: examples from the unshaped tunnel, threshold
	// set so that 5% of the browsing sessions are flagged.
	naiveTau := traffic.Quantile(nearestScores(plainTrain, benignCal), benignFPR)
	naive := struct{ plain, padded, benign float64 }{
		plain:  traffic.FlagRate(nearestScores(plainTrain, plainTest), naiveTau),
		padded: traffic.FlagRate(nearestScores(plainTrain, paddedTest), naiveTau),
		benign: traffic.FlagRate(nearestScores(plainTrain, benignTestSet), naiveTau),
	}

	// Adaptive template detector: examples from both tunnels.
	both := append(append([][]traffic.Step{}, plainTrain...), paddedTrain...)
	adaptiveTau := traffic.Quantile(nearestScores(both, benignCal), benignFPR)
	adaptive := struct{ plain, padded, benign float64 }{
		plain:  traffic.FlagRate(nearestScores(both, plainTest), adaptiveTau),
		padded: traffic.FlagRate(nearestScores(both, paddedTest), adaptiveTau),
		benign: traffic.FlagRate(nearestScores(both, benignTestSet), adaptiveTau),
	}

	t.Logf("share of sessions flagged:        no shaper  padding  browsing")
	t.Logf("equal-size detector                   %.2f     %.2f     %.2f", equal.plain, equal.padded, equal.benign)
	t.Logf("naive template detector               %.2f     %.2f     %.2f", naive.plain, naive.padded, naive.benign)
	t.Logf("adaptive template detector            %.2f     %.2f     %.2f", adaptive.plain, adaptive.padded, adaptive.benign)

	// The detectors must catch the unshaped tunnel and leave browsing mostly
	// alone, or the comparison says nothing.
	if equal.plain < 0.9 {
		t.Errorf("the equal-size detector flags only %.2f of unshaped sessions", equal.plain)
	}
	if naive.plain < 0.5 {
		t.Errorf("the naive template detector flags only %.2f of unshaped sessions", naive.plain)
	}
	if equal.benign > 0.3 || naive.benign > 0.3 {
		t.Errorf("too many browsing sessions flagged: equal-size %.2f, naive template %.2f", equal.benign, naive.benign)
	}
	// What padding is built to do: hide the run of equal-size records.
	if equal.padded > 0.2 {
		t.Errorf("padding left %.2f of sessions visible to the equal-size detector", equal.padded)
	}
	// The template detectors are reported and not asserted. Padding changes
	// sizes but not who speaks when, and the censor that matches on the
	// opening exchange keeps seeing it. That is the known limit, written up in
	// docs/threat-model.md.
}

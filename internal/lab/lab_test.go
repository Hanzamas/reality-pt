package lab

import (
	"math/rand/v2"
	"testing"

	"github.com/hanzamas/reality-pt/internal/traffic"
)

const (
	trainSessions = 20
	testSessions  = 20
	benignTrain   = 40
	benignTest    = 20
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

func templateScores(tmpl traffic.Template, traces [][]traffic.Step) []float64 {
	scores := make([]float64, len(traces))
	for i, tr := range traces {
		scores[i] = tmpl.Score(tr)
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

// TestShapingMovesWhatADetectorSees measures two stand-in censors against a
// tunnel without and with the padding shaper. Both detectors are made up for
// this project, and the browsing traffic is synthetic, so the numbers show
// whether shaping changes what can be seen and not how a real censor reacts.
func TestShapingMovesWhatADetectorSees(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a few seconds of local traffic")
	}
	rng := rand.New(rand.NewPCG(1, 2))

	plain := collectTunnel(t, "none", trainSessions+testSessions, rng)
	padded := collectTunnel(t, "padding", testSessions, rng)
	benign := collectBenign(t, benignTrain+benignTest, rng)

	// Detector 1: the start of the tunnel looks like the handshake of the
	// protocol inside it. The censor knows that shape from earlier traffic.
	tmpl := traffic.FitTemplate(plain[:trainSessions], firstSteps)
	tau := traffic.Quantile(templateScores(tmpl, benign[:benignTrain]), benignFPR)
	template := struct{ plain, padded, benign float64 }{
		plain:  traffic.FlagRate(templateScores(tmpl, plain[trainSessions:]), tau),
		padded: traffic.FlagRate(templateScores(tmpl, padded), tau),
		benign: traffic.FlagRate(templateScores(tmpl, benign[benignTrain:]), tau),
	}

	// Detector 2: a run of records of one size, which is what a stream of
	// fixed-size cells looks like and a browser does not produce.
	// A session is flagged when its modal share is above the 95th percentile of
	// the browsing sessions. On the negated values that is the 5th percentile.
	modalTau := traffic.Quantile(negModal(benign[:benignTrain]), benignFPR)
	modal := struct{ plain, padded, benign float64 }{
		plain:  traffic.FlagRate(negModal(plain[trainSessions:]), modalTau),
		padded: traffic.FlagRate(negModal(padded), modalTau),
		benign: traffic.FlagRate(negModal(benign[benignTrain:]), modalTau),
	}

	t.Logf("template detector, flagged: no shaper %.2f, padding %.2f, browsing %.2f", template.plain, template.padded, template.benign)
	t.Logf("equal-size detector, flagged: no shaper %.2f, padding %.2f, browsing %.2f", modal.plain, modal.padded, modal.benign)

	// The detectors must catch the unshaped tunnel, or the comparison says
	// nothing.
	if template.plain < 0.5 {
		t.Errorf("the template detector flags only %.2f of unshaped sessions", template.plain)
	}
	if modal.plain < 0.5 {
		t.Errorf("the equal-size detector flags only %.2f of unshaped sessions", modal.plain)
	}
	// Shaping must lower both.
	if template.padded >= template.plain {
		t.Errorf("padding did not lower the template detector: %.2f vs %.2f", template.padded, template.plain)
	}
	if modal.padded >= modal.plain {
		t.Errorf("padding did not lower the equal-size detector: %.2f vs %.2f", modal.padded, modal.plain)
	}
}

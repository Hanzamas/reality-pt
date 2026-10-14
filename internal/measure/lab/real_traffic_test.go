package lab

import (
	"math/rand/v2"
	"sort"
	"testing"

	"github.com/hanzamas/reality-pt/internal/measure/traffic"
	"github.com/hanzamas/reality-pt/shaper"
)

// realTracesPath is the file the shaper embeds. The traces were collected by
// the traces workflow from real sites.
const realTracesPath = "../../../shaper/data/real-openings.json"

// splitRealTraces divides the real traces by site. A shaper may follow the
// openings of the profile sites, and the comparison traffic is the openings of
// the other sites, which the shaper never saw. Judging a shaper against the
// traces it copies would only show that it copies them.
func splitRealTraces(t *testing.T) (profiles []shaper.Opening, comparison [][]traffic.Step) {
	t.Helper()
	file, err := traffic.ReadSaved(realTracesPath)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var sites []string
	for _, tr := range file.Traces {
		if !seen[tr.Site] {
			seen[tr.Site] = true
			sites = append(sites, tr.Site)
		}
	}
	sort.Strings(sites)
	profileSite := map[string]bool{}
	for i, site := range sites {
		profileSite[site] = i%2 == 0
	}

	for _, tr := range file.Traces {
		steps := tr.AsSteps()
		if !profileSite[tr.Site] {
			comparison = append(comparison, steps)
			continue
		}
		var o shaper.Opening
		for _, s := range steps {
			o.Steps = append(o.Steps, shaper.OpeningStep{Up: s.Up, Len: s.Len})
		}
		profiles = append(profiles, o)
	}
	if len(profiles) < 20 || len(comparison) < 40 {
		t.Fatalf("too few real traces: %d profiles, %d for comparison", len(profiles), len(comparison))
	}
	return profiles, comparison
}

// TestShapersAgainstRealTraffic compares the shapers with openings of real
// HTTPS connections. The detectors are the template detectors from the other
// test, with the false alarm rate set on real traffic. It prints, for each
// shaper, the share of tunnels flagged by a censor that knows how an unshaped
// tunnel starts (naive) and by one that has also seen tunnels of that shaper
// (adaptive).
//
// The detectors are simple and were written for this project. A low number
// here is not proof of anything against a real censor. A high one is a real
// weakness.
func TestShapersAgainstRealTraffic(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a few seconds of local traffic")
	}
	rng := rand.New(rand.NewPCG(7, 8))
	profiles, comparison := splitRealTraces(t)
	calibration, held := comparison[:len(comparison)/2], comparison[len(comparison)/2:]

	shapers := []struct {
		name string
		s    shaper.Shaper
	}{
		{"no shaper", shaper.Noop{}},
		{"padding", shaper.NewPadding(shaper.DefaultPadding)},
		{"morph", shaper.NewMorph(shaper.MorphConfig{Openings: profiles, Later: shaper.DefaultPadding})},
	}
	sessions := make([][][]traffic.Step, len(shapers))
	for i, sh := range shapers {
		bridge := StartBridgeWith(t, Local, sh.s)
		for n := 0; n < trainSessions+testSessions; n++ {
			sessions[i] = append(sessions[i], bridge.TorLikeSession(t, rng))
		}
	}
	plainTrain := sessions[0][:trainSessions]

	// A censor flags a session when it is closer to a known tunnel than all but
	// 5% of the real traffic in the calibration set.
	flagged := func(known, test [][]traffic.Step) float64 {
		tau := traffic.Quantile(nearestScores(known, calibration), benignFPR)
		return traffic.FlagRate(nearestScores(known, test), tau)
	}

	t.Logf("share of tunnels flagged            naive censor   adaptive censor")
	var naiveNone float64
	for i, sh := range shapers {
		train, test := sessions[i][:trainSessions], sessions[i][trainSessions:]
		adaptiveKnown := append(append([][]traffic.Step{}, plainTrain...), train...)
		naive := flagged(plainTrain, test)
		adaptive := flagged(adaptiveKnown, test)
		if i == 0 {
			naiveNone = naive
		}
		t.Logf("%-34s %.2f           %.2f", sh.name, naive, adaptive)
	}
	// The same censors on real traffic that neither they nor the shapers saw.
	adaptiveReal := flagged(append(append([][]traffic.Step{}, plainTrain...), sessions[2][:trainSessions]...), held)
	t.Logf("%-34s %.2f           %.2f", "real traffic (false alarms)", flagged(plainTrain, held), adaptiveReal)

	// The comparison only means something if the censor catches an unshaped
	// tunnel and leaves real traffic mostly alone.
	if naiveNone < 0.5 {
		t.Errorf("the naive censor flags only %.2f of unshaped tunnels", naiveNone)
	}
	if fa := flagged(plainTrain, held); fa > 0.25 {
		t.Errorf("the naive censor flags %.2f of real traffic it never saw", fa)
	}
}

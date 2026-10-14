package traffic

import (
	"math"
	"slices"
)

// Template is the typical start of one kind of traffic: for each of the first
// positions, a direction and a length.
type Template struct {
	steps []Step
}

// FitTemplate builds a template from the first n steps of several traces. At
// each position it takes the direction most traces share and the median length
// among the traces that agree with it.
func FitTemplate(traces [][]Step, n int) Template {
	var t Template
	for i := 0; i < n; i++ {
		var up, down int
		for _, tr := range traces {
			if i < len(tr) {
				if tr[i].Up {
					up++
				} else {
					down++
				}
			}
		}
		dir := up >= down
		var lens []float64
		for _, tr := range traces {
			if i < len(tr) && tr[i].Up == dir {
				lens = append(lens, float64(tr[i].Len))
			}
		}
		t.steps = append(t.steps, Step{Up: dir, Len: int(Median(lens))})
	}
	return t
}

// penalty caps what one position can add to a score.
const penalty = 3.0

// Score says how far steps are from the template. Lower means closer. A
// position adds the distance between the lengths on a log2 scale, or the full
// penalty if the direction differs or the trace is shorter.
func (t Template) Score(steps []Step) float64 {
	if len(t.steps) == 0 {
		return penalty
	}
	var total float64
	for i, want := range t.steps {
		if i >= len(steps) || steps[i].Up != want.Up {
			total += penalty
			continue
		}
		d := math.Abs(math.Log2(float64(steps[i].Len+16) / float64(want.Len+16)))
		total += math.Min(d, penalty)
	}
	return total / float64(len(t.steps))
}

// ModalShare is the share of the first k records in one direction that have
// the most common length. Traffic made of equal-size units, such as Tor cells,
// scores high.
func ModalShare(steps []Step, up bool, k int) float64 {
	counts := map[int]int{}
	seen := 0
	for _, s := range steps {
		if s.Up != up {
			continue
		}
		counts[s.Len]++
		if seen++; seen == k {
			break
		}
	}
	if seen == 0 {
		return 0
	}
	most := 0
	for _, c := range counts {
		most = max(most, c)
	}
	return float64(most) / float64(seen)
}

// Median returns the middle value of xs, or 0 for an empty slice.
func Median(xs []float64) float64 { return Quantile(xs, 0.5) }

// Quantile returns the value below which a share q of xs lies, by nearest
// rank. It returns 0 for an empty slice.
func Quantile(xs []float64, q float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sorted := slices.Clone(xs)
	slices.Sort(sorted)
	i := int(q * float64(len(sorted)))
	return sorted[min(max(i, 0), len(sorted)-1)]
}

// FlagRate is the share of values that are below threshold.
func FlagRate(values []float64, threshold float64) float64 {
	if len(values) == 0 {
		return 0
	}
	flagged := 0
	for _, v := range values {
		if v < threshold {
			flagged++
		}
	}
	return float64(flagged) / float64(len(values))
}

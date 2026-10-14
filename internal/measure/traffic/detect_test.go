package traffic

import (
	"math"
	"testing"
)

func TestRecordParserSplitsAStream(t *testing.T) {
	rec := func(typ byte, n int) []byte {
		return append([]byte{typ, 3, 3, byte(n >> 8), byte(n)}, make([]byte, n)...)
	}
	whole := append(append(rec(TypeHandshake, 300), rec(TypeApplicationData, 40)...), rec(TypeApplicationData, 1000)...)

	// Feed it in pieces of 17 bytes, which split headers and bodies.
	p := &recordParser{up: true}
	var records []Record
	for i := 0; i < len(whole); i += 17 {
		records = append(records, p.feed(whole[i:min(i+17, len(whole))])...)
	}
	want := []Record{
		{Up: true, Type: TypeHandshake, Len: 300},
		{Up: true, Type: TypeApplicationData, Len: 40},
		{Up: true, Type: TypeApplicationData, Len: 1000},
	}
	if len(records) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(records), len(want), records)
	}
	for i := range want {
		if records[i] != want[i] {
			t.Errorf("record %d = %+v, want %+v", i, records[i], want[i])
		}
	}
}

func TestRecordParserGivesUpOnNonTLS(t *testing.T) {
	p := &recordParser{}
	if got := p.feed([]byte("GET / HTTP/1.1\r\n\r\n")); len(got) != 0 {
		t.Fatalf("parsed records out of HTTP: %+v", got)
	}
	if got := p.feed([]byte{23, 3, 3, 0, 1, 0}); len(got) != 0 {
		t.Fatal("a stream that was abandoned produced records again")
	}
}

func TestAfterHandshakeStartsAfterTheClientsFirstApplicationData(t *testing.T) {
	records := []Record{
		{Up: true, Type: TypeHandshake, Len: 500},
		{Up: false, Type: TypeHandshake, Len: 90},
		{Up: false, Type: TypeChangeCipherSpec, Len: 1},
		{Up: false, Type: TypeApplicationData, Len: 3000}, // server flight
		{Up: true, Type: TypeChangeCipherSpec, Len: 1},
		{Up: true, Type: TypeApplicationData, Len: 74}, // client Finished
		{Up: false, Type: TypeApplicationData, Len: 250},
		{Up: true, Type: TypeApplicationData, Len: 600},
		{Up: false, Type: TypeAlert, Len: 2},
	}
	got := AfterHandshake(records)
	want := []Step{{Up: false, Len: 250}, {Up: true, Len: 600}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("AfterHandshake = %+v, want %+v", got, want)
	}
	if AfterHandshake(records[:3]) != nil {
		t.Fatal("a trace without client application data produced steps")
	}
}

func TestTemplateScoresSimilarTrafficLower(t *testing.T) {
	var traces [][]Step
	for i := 0; i < 11; i++ {
		traces = append(traces, []Step{
			{Up: true, Len: 500 + i},
			{Up: false, Len: 3000 - i},
			{Up: true, Len: 80},
		})
	}
	tmpl := FitTemplate(traces, 3)

	same := tmpl.Score([]Step{{Up: true, Len: 505}, {Up: false, Len: 2995}, {Up: true, Len: 80}})
	other := tmpl.Score([]Step{{Up: false, Len: 40}, {Up: true, Len: 9000}, {Up: false, Len: 1200}})
	if same > 0.1 {
		t.Errorf("a trace like the template scored %v", same)
	}
	if other < 1 {
		t.Errorf("a trace unlike the template scored %v", other)
	}
	if got := tmpl.Score(nil); math.Abs(got-penalty) > 1e-9 {
		t.Errorf("an empty trace scored %v, want the penalty %v", got, penalty)
	}
}

func TestModalShare(t *testing.T) {
	steps := []Step{{true, 556}, {true, 556}, {true, 556}, {true, 90}, {false, 1200}, {false, 1300}}
	if got := ModalShare(steps, true, 10); math.Abs(got-0.75) > 1e-9 {
		t.Errorf("upstream modal share = %v, want 0.75", got)
	}
	if got := ModalShare(steps, false, 10); math.Abs(got-0.5) > 1e-9 {
		t.Errorf("downstream modal share = %v, want 0.5", got)
	}
	if got := ModalShare(nil, true, 10); got != 0 {
		t.Errorf("modal share of nothing = %v", got)
	}
}

func TestQuantileAndFlagRate(t *testing.T) {
	xs := []float64{5, 1, 4, 2, 3}
	if got := Median(xs); got != 3 {
		t.Errorf("median = %v", got)
	}
	if got := Quantile(xs, 0); got != 1 {
		t.Errorf("minimum = %v", got)
	}
	if got := Quantile(xs, 1); got != 5 {
		t.Errorf("maximum = %v", got)
	}
	if got := FlagRate(xs, 3); math.Abs(got-0.4) > 1e-9 {
		t.Errorf("flag rate = %v, want 0.4", got)
	}
	if Median(nil) != 0 || FlagRate(nil, 1) != 0 {
		t.Error("empty input must give 0")
	}
}

package cbt

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

const unlearned = 30 * time.Second

// paretoSample draws a build time from a Pareto curve with the given Xm and
// alpha (inverse transform sampling), with a deterministic source.
func paretoSample(r *rand.Rand, xm, alpha float64) time.Duration {
	u := r.Float64()
	ms := xm / math.Pow(1-u, 1/alpha)
	return time.Duration(ms * float64(time.Millisecond))
}

// TestUnlearnedTimeouts uses the caller's timeout until enough build times
// are recorded, and the consensus's initial timeout to close.
func TestUnlearnedTimeouts(t *testing.T) {
	e := New(DefaultParams(), unlearned)
	soft, closeTimeout := e.Timeouts(3)
	if soft != unlearned || closeTimeout != 60*time.Second {
		t.Fatalf("soft %v close %v", soft, closeTimeout)
	}
	if !e.NeedsCircuits() {
		t.Fatal("no circuits needed without observations")
	}
	for range 99 {
		e.Record(time.Second)
	}
	if learned, n := e.Learned(); learned || n != 99 {
		t.Fatalf("learned=%v after %d", learned, n)
	}
	e.Record(time.Second)
	if learned, _ := e.Learned(); !learned || e.NeedsCircuits() {
		t.Fatal("not learned after cbtmincircs observations")
	}
}

// TestLearnsParetoQuantiles recovers the timeouts of a known Pareto curve:
// the soft timeout near its 80% point and the close timeout near its 99%
// point (capped to the spec's limits).
func TestLearnsParetoQuantiles(t *testing.T) {
	const xm, alpha = 800.0, 2.5
	e := New(DefaultParams(), unlearned)
	r := rand.New(rand.NewPCG(1, 2))
	for range observations {
		e.Record(paretoSample(r, xm, alpha))
	}

	want80 := xm / math.Pow(0.2, 1/alpha) // 1525 ms
	soft, closeTimeout := e.Timeouts(3)
	if got := float64(soft.Milliseconds()); math.Abs(got-want80)/want80 > 0.15 {
		t.Fatalf("soft timeout %v, want about %.0fms", soft, want80)
	}
	// The 99% point (5 s here) is below the initial timeout, which is the
	// floor of the close timeout.
	if closeTimeout != 60*time.Second {
		t.Fatalf("close timeout %v", closeTimeout)
	}
	st := e.Stats()
	if math.Abs(st.Alpha-alpha)/alpha > 0.25 || st.Observations != observations {
		t.Fatalf("stats %+v", st)
	}

	// Four-hop circuits get 10/6 of the three-hop timeouts.
	soft4, _ := e.Timeouts(4)
	if want := soft * 10 / 6; soft4 < want-time.Millisecond || soft4 > want+time.Millisecond {
		t.Fatalf("4-hop soft timeout %v, want %v", soft4, want)
	}
}

// TestTimeoutCappedAtMaxObserved never waits longer than the longest build
// actually observed, and closes no later than twice it (but no sooner than
// the initial timeout).
func TestTimeoutCappedAtMaxObserved(t *testing.T) {
	p := DefaultParams()
	p.InitialTimeout = 500 * time.Millisecond
	p.NumModes = 1

	// All times equal: Xm is the 1005 ms bin midpoint, above every time.
	e := New(p, unlearned)
	for range 100 {
		e.Record(time.Second)
	}
	soft, closeTimeout := e.Timeouts(3)
	if soft != time.Second || closeTimeout != 1005*time.Millisecond {
		t.Fatalf("soft %v close %v", soft, closeTimeout)
	}

	// A heavy tail: the 99% point (about 19 s) is far beyond twice the
	// 1 s maximum.
	e = New(p, unlearned)
	for range 50 {
		e.Record(100 * time.Millisecond)
		e.Record(time.Second)
	}
	soft, closeTimeout = e.Timeouts(3)
	if closeTimeout != 2*time.Second {
		t.Fatalf("close %v, want twice the maximum", closeTimeout)
	}
	if soft >= time.Second || soft < 500*time.Millisecond {
		t.Fatalf("soft %v, want about 644ms", soft)
	}
}

// TestRecordDiscardsClockJumps ignores build times beyond twice the close
// timeout (the device slept or the clock jumped).
func TestRecordDiscardsClockJumps(t *testing.T) {
	e := New(DefaultParams(), unlearned)
	e.Record(122 * time.Second) // close is 60 s: beyond 2*60s+1s
	e.Record(-time.Second)
	if _, n := e.Learned(); n != 0 {
		t.Fatalf("%d strange times recorded", n)
	}
	e.Record(100 * time.Second)
	if _, n := e.Learned(); n != 1 {
		t.Fatal("a long but plausible time was discarded")
	}
}

// TestNetworkChangeResets discards the history when cbtmaxtimeouts of the
// last cbtrecentcount circuits timed out after their first hop, and doubles
// a timeout that was already at least the initial one.
func TestNetworkChangeResets(t *testing.T) {
	e := New(DefaultParams(), unlearned)
	for range 100 {
		e.Record(time.Second)
	}
	// Timeouts before the first hop (no network) don't count.
	for range 30 {
		if e.TimedOut(false) {
			t.Fatal("reset without a first hop")
		}
	}
	for i := range 18 {
		reset := e.TimedOut(true)
		if reset != (i == 17) {
			t.Fatalf("timeout %d: reset=%v", i+1, reset)
		}
	}
	if learned, n := e.Learned(); learned || n != 0 {
		t.Fatalf("history kept: learned=%v n=%d", learned, n)
	}
	if soft, _ := e.Timeouts(3); soft != unlearned {
		t.Fatalf("soft %v after reset", soft)
	}

	// Successes interleaved keep it below the threshold.
	for range 40 {
		e.TimedOut(true)
		e.Completed()
	}
	if soft, _ := e.Timeouts(3); soft != unlearned {
		t.Fatal("reset counted successes")
	}

	// With a timeout of at least the initial one, a reset doubles it.
	p := DefaultParams()
	p.InitialTimeout = 20 * time.Second
	slow := New(p, unlearned)
	for range 18 {
		slow.TimedOut(true)
	}
	if soft, _ := slow.Timeouts(3); soft != 60*time.Second {
		t.Fatalf("soft %v, want the 30 s timeout doubled", soft)
	}
}

// TestAbandonedObservations count towards the history but not the curve.
func TestAbandonedObservations(t *testing.T) {
	e := New(DefaultParams(), unlearned)
	for range 90 {
		e.Record(time.Second)
	}
	for range 10 {
		e.Abandoned()
	}
	st := e.Stats()
	if !st.Learned || st.Abandoned != 10 || st.Observations != 100 {
		t.Fatalf("stats %+v", st)
	}
	if st.Xm != 1005*time.Millisecond {
		t.Fatalf("Xm %v includes abandoned circuits", st.Xm)
	}
}

// TestXmUsesModes averages the most frequent bins, weighted by their counts.
func TestXmUsesModes(t *testing.T) {
	p := DefaultParams()
	p.NumModes = 2
	e := New(p, unlearned)
	add := func(ms, n int) {
		for range n {
			e.Record(time.Duration(ms) * time.Millisecond)
		}
	}
	add(500, 50)  // bin midpoint 505
	add(1000, 30) // bin midpoint 1005
	add(1500, 20) // third most frequent: not a mode
	// (505*50 + 1005*30) / 80 = 692 (integer division, like C tor)
	if xm := e.Stats().Xm; xm != 692*time.Millisecond {
		t.Fatalf("Xm %v", xm)
	}
}

// TestStateRoundTrip persists the histogram and restores the same timeout.
func TestStateRoundTrip(t *testing.T) {
	e := New(DefaultParams(), unlearned)
	r := rand.New(rand.NewPCG(3, 4))
	for range 500 {
		e.Record(paretoSample(r, 600, 3))
	}
	e.Abandoned()
	data, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	restored := New(DefaultParams(), unlearned)
	if err := restored.Load(data); err != nil {
		t.Fatal(err)
	}
	a, b := e.Stats(), restored.Stats()
	if b.Observations != a.Observations || b.Abandoned != 1 || !b.Learned {
		t.Fatalf("restored %+v from %+v", b, a)
	}
	// Times are restored at their bin midpoints: within 5 ms each.
	orig, back := e.sortedTimes(), restored.sortedTimes()
	for i := range orig {
		if d := orig[i] - back[i]; d < -5 || d > 5 {
			t.Fatalf("time %d: %d vs %d", i, orig[i], back[i])
		}
	}
	if d := a.SoftTimeout - b.SoftTimeout; d < -20*time.Millisecond || d > 20*time.Millisecond {
		t.Fatalf("soft timeout %v vs %v", a.SoftTimeout, b.SoftTimeout)
	}
}

// TestLoadKeepsAtMostTheHistory keeps 1000 random observations of a larger
// state and rejects corrupt ones.
func TestLoadKeepsAtMostTheHistory(t *testing.T) {
	e := New(DefaultParams(), unlearned)
	if err := e.Load([]byte(`{"version":1,"bins":[[1005,1500]],"abandoned":0}`)); err != nil {
		t.Fatal(err)
	}
	if _, n := e.Learned(); n != observations {
		t.Fatalf("%d observations", n)
	}
	for _, bad := range []string{
		`not json`,
		`{"version":2,"bins":[]}`,
		`{"version":1,"bins":[[0,1]]}`,
		`{"version":1,"bins":[[1005,20000]]}`,
		`{"version":1,"bins":[],"abandoned":20000}`,
		`{"version":1,"bins":[[2147483646,1]]}`,
	} {
		if err := New(DefaultParams(), unlearned).Load([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

// TestParamsFromConsensus reads the cbt* parameters within their bounds.
func TestParamsFromConsensus(t *testing.T) {
	def := DefaultParams()
	if def.MinCircs != 100 || def.Quantile != 0.8 || def.CloseQuantile != 0.99 ||
		def.InitialTimeout != time.Minute || def.TestFrequency != 10*time.Second ||
		def.MaxOpenCircs != 10 || def.RecentCount != 20 || def.MaxTimeouts != 18 ||
		def.NumModes != 10 || def.MinTimeout != 10*time.Millisecond || def.Disabled {

		t.Fatalf("defaults %+v", def)
	}
	c := &common.Consensus{Params: map[string]int32{
		"cbtdisabled":      1,
		"cbtquantile":      70,
		"cbtclosequantile": 50, // below cbtquantile: raised to it
		"cbtnummodes":      99, // above the maximum
		"cbtmincircs":      0,  // below the minimum
	}}
	p := ParamsFrom(c)
	if !p.Disabled || p.Quantile != 0.7 || p.CloseQuantile != 0.7 ||
		p.NumModes != 20 || p.MinCircs != 1 {

		t.Fatalf("params %+v", p)
	}
}

// TestDisabled ignores observations and uses the unlearned timeouts.
func TestDisabled(t *testing.T) {
	e := New(DefaultParams(), unlearned)
	for range 100 {
		e.Record(time.Second)
	}
	p := DefaultParams()
	p.Disabled = true
	e.SetParams(p)
	if learned, n := e.Learned(); learned || n != 0 || e.NeedsCircuits() {
		t.Fatal("history kept while disabled")
	}
	e.Record(time.Second)
	if _, n := e.Learned(); n != 0 {
		t.Fatal("recorded while disabled")
	}
	if soft, _ := e.Timeouts(3); soft != unlearned {
		t.Fatalf("soft %v while disabled", soft)
	}
}

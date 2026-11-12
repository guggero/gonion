// Package cbt learns when to give up on building a circuit (path-spec,
// "Learning when to give up ('timeout') on circuit construction"), following
// C tor's circuitstats.c: it records how long the first three hops of
// circuits take to build, fits a Pareto curve to the tail of those build
// times, and derives a soft timeout, after which a circuit is no longer
// waited for, and a close timeout, after which it is abandoned.
package cbt

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

const (
	// observations is how many build times are kept (CBT_NCIRCUITS_TO_OBSERVE).
	observations = 1000

	// binWidth is the width of a histogram bin in milliseconds (CBT_BIN_WIDTH).
	binWidth = 10

	// abandoned marks an observation of a circuit that reached the close
	// timeout without completing (CBT_BUILD_ABANDONED).
	abandoned = math.MaxInt32 - 1

	// maxBuildTime is the largest build time in milliseconds that can be
	// recorded (CBT_BUILD_TIME_MAX).
	maxBuildTime = math.MaxInt32

	// saveEvery is how many new observations trigger a save
	// (CBT_SAVE_STATE_EVERY).
	saveEvery = 10

	// recordedHops is the circuit length build times are recorded for
	// (DEFAULT_ROUTE_LEN).
	recordedHops = 3
)

// Params are the consensus parameters governing timeout learning (path-spec,
// "Consensus parameters governing behavior").
type Params struct {
	Disabled       bool
	NumModes       int
	RecentCount    int
	MaxTimeouts    int
	MinCircs       int
	Quantile       float64 // 0.10 to 0.99
	CloseQuantile  float64 // Quantile to 0.99
	TestFrequency  time.Duration
	MinTimeout     time.Duration
	InitialTimeout time.Duration
	MaxOpenCircs   int
}

// DefaultParams are the parameters without a consensus.
func DefaultParams() Params {
	return ParamsFrom(nil)
}

// ParamsFrom reads the cbt* parameters of a consensus, with the spec's
// defaults and bounds.
func ParamsFrom(c *common.Consensus) Params {
	param := func(name string, def, lo, hi int32) int {
		return c.Parameter(name, def, lo, hi)
	}
	quantile := param("cbtquantile", 80, 10, 99)
	minTimeout := param("cbtmintimeout", binWidth, binWidth, math.MaxInt32)
	return Params{
		Disabled:       param("cbtdisabled", 0, 0, 1) == 1,
		NumModes:       param("cbtnummodes", 10, 1, 20),
		RecentCount:    param("cbtrecentcount", 20, 3, 1000),
		MaxTimeouts:    param("cbtmaxtimeouts", 18, 3, 10000),
		MinCircs:       param("cbtmincircs", 100, 1, 10000),
		Quantile:       float64(quantile) / 100,
		CloseQuantile:  float64(param("cbtclosequantile", 99, int32(quantile), 99)) / 100,
		TestFrequency:  time.Duration(param("cbttestfreq", 10, 1, math.MaxInt32)) * time.Second,
		MinTimeout:     time.Duration(minTimeout) * time.Millisecond,
		InitialTimeout: time.Duration(param("cbtinitialtimeout", 60000, int32(minTimeout), math.MaxInt32)) * time.Millisecond,
		MaxOpenCircs:   param("cbtmaxopencircs", 10, 0, 14),
	}
}

// Estimator holds the recorded build times and the timeouts derived from
// them. It is safe for concurrent use.
type Estimator struct {
	mu sync.Mutex
	p  Params

	// unlearned is the soft timeout used until enough build times are
	// recorded.
	unlearned time.Duration

	times [observations]int32 // build times in ms; 0 is empty
	next  int                 // the slot the next observation goes to
	total int                 // the number of observations (at most 1000)
	dirty int                 // observations since the last save

	learned        bool
	timeoutMs      float64
	closeMs        float64
	xm, alpha      float64
	resetTimeoutMs float64 // a doubled timeout after a reset, or 0

	recent    []bool // timeouts after the first hop of recent circuits
	recentIdx int
}

// New returns an estimator without observations. Until it has learned a
// timeout, the soft timeout is unlearned and the close timeout the
// consensus's initial timeout (at least unlearned).
func New(p Params, unlearned time.Duration) *Estimator {
	e := &Estimator{p: p, unlearned: unlearned}
	e.recent = make([]bool, p.RecentCount)
	return e
}

// SetParams applies the parameters of a new consensus.
func (e *Estimator) SetParams(p Params) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if p.Disabled && !e.p.Disabled {
		e.resetLocked()
	}
	if p.RecentCount != len(e.recent) {
		e.recent = make([]bool, p.RecentCount)
		e.recentIdx = 0
	}
	e.p = p
	e.computeLocked()
}

// Timeouts returns the soft and close timeouts for a circuit of the given
// number of hops, scaled from the three-hop timeouts by the number of round
// trips its construction needs (path-spec: Actions(N) = N*(N+1)/2).
func (e *Estimator) Timeouts(hops int) (soft, closeTimeout time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	softMs, closeMs := e.timeoutsLocked()
	scale := float64(actions(max(hops, 1))) / float64(actions(recordedHops))
	return msDuration(softMs * scale), msDuration(closeMs * scale)
}

func (e *Estimator) timeoutsLocked() (float64, float64) {
	initial := float64(e.p.InitialTimeout.Milliseconds())
	if e.learned && !e.p.Disabled {
		return e.timeoutMs, e.closeMs
	}
	soft := float64(e.unlearned.Milliseconds())
	if e.resetTimeoutMs > 0 {
		soft = e.resetTimeoutMs
	}
	return soft, max(initial, soft)
}

func actions(hops int) int { return hops * (hops + 1) / 2 }

func msDuration(ms float64) time.Duration {
	return time.Duration(ms * float64(time.Millisecond))
}

// Learned reports whether a timeout has been learned, and from how many
// observations.
func (e *Estimator) Learned() (bool, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.learned && !e.p.Disabled, e.total
}

// NeedsCircuits reports whether fewer build times are recorded than needed
// to learn a timeout, so test circuits are worth building.
func (e *Estimator) NeedsCircuits() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.p.Disabled && e.total < e.p.MinCircs
}

// Record adds the time a circuit took to open its first three hops,
// including a circuit that passed the soft timeout and kept building for
// measurement. A time beyond twice the close timeout is discarded: the
// clock jumped or the device slept. It returns true when the state should
// be saved.
func (e *Estimator) Record(d time.Duration) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.p.Disabled {
		return false
	}
	_, closeMs := e.timeoutsLocked()
	ms := d.Milliseconds()
	if ms <= 0 || float64(ms) > 2*closeMs+1000 || ms >= abandoned {
		return false
	}
	e.addLocked(int32(ms))
	e.computeLocked()
	return e.dirty >= saveEvery
}

// Abandoned records a circuit that reached the close timeout without opening
// its third hop. Callers only report circuits that opened their first hop,
// so time without network isn't counted. It returns true when the state
// should be saved.
func (e *Estimator) Abandoned() bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.p.Disabled {
		return false
	}
	e.addLocked(abandoned)
	e.computeLocked()
	return e.dirty >= saveEvery
}

// Completed notes a circuit that built before its soft timeout, for
// detecting changed network conditions.
func (e *Estimator) Completed() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.recent) == 0 {
		return
	}
	e.recent[e.recentIdx] = false
	e.recentIdx = (e.recentIdx + 1) % len(e.recent)
}

// TimedOut notes a circuit that passed its soft timeout. If it had opened
// its first hop, it counts towards detecting changed network conditions:
// when MaxTimeouts of the last RecentCount circuits timed out, the history
// is discarded and learning starts over (path-spec, "Detecting Changing
// Network Conditions"). It returns true if that happened.
func (e *Estimator) TimedOut(didOneHop bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.p.Disabled || !didOneHop || len(e.recent) == 0 {
		return false
	}
	e.recent[e.recentIdx] = true
	e.recentIdx = (e.recentIdx + 1) % len(e.recent)

	count := 0
	for _, timedOut := range e.recent {
		if timedOut {
			count++
		}
	}
	if count < e.p.MaxTimeouts {
		return false
	}

	// If the timeout was already at least the initial one, the network is
	// abysmal: double it instead of starting from the initial value.
	previous, _ := e.timeoutsLocked()
	initial := float64(e.p.InitialTimeout.Milliseconds())
	e.resetLocked()
	if previous >= initial && previous <= math.MaxInt32/2 {
		e.resetTimeoutMs = 2 * previous
	}
	return true
}

// resetLocked discards all observations and the learned timeout.
func (e *Estimator) resetLocked() {
	e.times = [observations]int32{}
	e.next, e.total, e.dirty = 0, 0, 0
	e.learned = false
	e.timeoutMs, e.closeMs, e.xm, e.alpha = 0, 0, 0, 0
	e.resetTimeoutMs = 0
	for i := range e.recent {
		e.recent[i] = false
	}
	e.recentIdx = 0
}

func (e *Estimator) addLocked(ms int32) {
	e.times[e.next] = ms
	e.next = (e.next + 1) % observations
	if e.total < observations {
		e.total++
	}
	e.dirty++
}

// computeLocked derives the timeouts once enough build times are recorded
// (C tor's circuit_build_times_set_timeout_worker).
func (e *Estimator) computeLocked() {
	if e.p.Disabled || e.total < e.p.MinCircs {
		return
	}
	xm := e.xmLocked()
	if xm == 0 {
		return
	}

	// alpha = n / (Sum ln(max(Xm, x_i)) - n ln(Xm)), over the completed
	// circuits only.
	var sum float64
	n := 0
	for _, t := range e.times[:] {
		if t == 0 || t == abandoned {
			continue
		}
		sum += math.Log(max(xm, float64(t)))
		n++
	}
	if n == 0 {
		return
	}
	// All times at or below Xm make the denominator zero (up to rounding)
	// and alpha infinite: the quantiles are then Xm itself.
	alpha := math.Inf(1)
	if denominator := sum - float64(n)*math.Log(xm); denominator > 1e-9 {
		alpha = float64(n) / denominator
	}

	timeout := quantile(xm, alpha, e.p.Quantile)
	closeTimeout := quantile(xm, alpha, e.p.CloseQuantile)

	// Cap at the observed maximum (and the close timeout at twice it),
	// but close no sooner than the initial timeout.
	maxObserved := float64(e.maxLocked())
	timeout = min(timeout, maxObserved)
	if maxObserved < math.MaxInt32/2 {
		closeTimeout = min(closeTimeout, 2*maxObserved)
	}
	closeTimeout = max(closeTimeout, float64(e.p.InitialTimeout.Milliseconds()))
	timeout = max(timeout, float64(e.p.MinTimeout.Milliseconds()))

	e.xm, e.alpha = xm, alpha
	e.timeoutMs, e.closeMs = timeout, closeTimeout
	e.learned = true
	e.resetTimeoutMs = 0
}

// quantile is the Pareto quantile function: the build time below which the
// share q of circuits completes, clamped to the int32 milliseconds C tor
// uses.
func quantile(xm, alpha, q float64) float64 {
	p := math.Pow(1-q, 1/alpha)
	if p <= 0 {
		return math.MaxInt32
	}
	return min(xm/p, math.MaxInt32)
}

// maxLocked returns the longest recorded build time.
func (e *Estimator) maxLocked() int32 {
	var longest int32
	for _, t := range e.times[:] {
		if t != abandoned && t > longest {
			longest = t
		}
	}
	return longest
}

// histogramLocked counts the completed build times per 10 ms bin.
func (e *Estimator) histogramLocked() []uint32 {
	bins := make([]uint32, e.maxLocked()/binWidth+1)
	for _, t := range e.times[:] {
		if t == 0 || t == abandoned {
			continue
		}
		bins[t/binWidth]++
	}
	return bins
}

// xmLocked is the Pareto Xm: the average of the midpoints of the NumModes
// most frequent bins, weighted by their counts, ties going to the shorter
// times (C tor's circuit_build_times_get_xm).
func (e *Estimator) xmLocked() float64 {
	bins := e.histogramLocked()
	var total, count uint64
	for range e.p.NumModes {
		best := 0
		for i, n := range bins {
			if n > bins[best] {
				best = i
			}
		}
		total += uint64(binMidpoint(best)) * uint64(bins[best])
		count += uint64(bins[best])
		bins[best] = 0
	}
	if count == 0 {
		return 0
	}
	return float64(total / count)
}

func binMidpoint(bin int) int { return bin*binWidth + binWidth/2 }

// state is the persisted form: a histogram like C tor's state file
// (CircuitBuildTimeBin, CircuitBuildAbandonedCount).
type state struct {
	Version   int         `json:"version"`
	Bins      [][2]uint32 `json:"bins"` // [bin midpoint ms, count]
	Abandoned uint32      `json:"abandoned"`
}

const stateVersion = 1

// Marshal returns the observations as a histogram for persistence, and
// clears the save trigger.
func (e *Estimator) Marshal() ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	s := state{Version: stateVersion, Bins: [][2]uint32{}}
	for i, n := range e.histogramLocked() {
		if n != 0 {
			s.Bins = append(s.Bins, [2]uint32{uint32(binMidpoint(i)), n})
		}
	}
	for _, t := range e.times[:] {
		if t == abandoned {
			s.Abandoned++
		}
	}
	e.dirty = 0
	return json.Marshal(s)
}

// Load replaces the observations with a persisted histogram. The times are
// shuffled (keeping at most 1000 at random) so that old values still expire
// in a random order (path-spec: "The timeouts recorded in the histogram
// must be shuffled after being read from disk").
func (e *Estimator) Load(data []byte) error {
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("cbt: invalid state: %w", err)
	}
	if s.Version != stateVersion {
		return fmt.Errorf("cbt: unsupported state version %d", s.Version)
	}

	// Bound the expansion: more than ten times the history is corrupt.
	const limit = 10 * observations
	var times []int32
	count := uint64(s.Abandoned)
	for _, bin := range s.Bins {
		ms, n := bin[0], bin[1]
		count += uint64(n)
		if ms == 0 || ms >= abandoned || count > limit {
			return fmt.Errorf("cbt: invalid state bin %v", bin)
		}
		for range n {
			times = append(times, int32(ms))
		}
	}
	if count > limit {
		return fmt.Errorf("cbt: too many observations in state")
	}
	for range s.Abandoned {
		times = append(times, abandoned)
	}
	if err := shuffle(times); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.times = [observations]int32{}
	e.next, e.total, e.dirty = 0, 0, 0
	e.learned = false
	for _, t := range times[:min(len(times), observations)] {
		e.addLocked(t)
	}
	e.dirty = 0
	e.computeLocked()
	return nil
}

// shuffle permutes the times with crypto/rand.
func shuffle(times []int32) error {
	for i := len(times) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("cbt: shuffle: %w", err)
		}
		times[i], times[j.Int64()] = times[j.Int64()], times[i]
	}
	return nil
}

// Stats is a snapshot of the learned parameters.
type Stats struct {
	Learned      bool
	Observations int
	Abandoned    int
	SoftTimeout  time.Duration
	CloseTimeout time.Duration
	Xm           time.Duration
	Alpha        float64
}

// Stats returns the current timeouts and the curve they come from.
func (e *Estimator) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()

	softMs, closeMs := e.timeoutsLocked()
	s := Stats{
		Learned:      e.learned && !e.p.Disabled,
		Observations: e.total,
		SoftTimeout:  msDuration(softMs),
		CloseTimeout: msDuration(closeMs),
		Xm:           msDuration(e.xm),
		Alpha:        e.alpha,
	}
	for _, t := range e.times[:] {
		if t == abandoned {
			s.Abandoned++
		}
	}
	return s
}

// sortedTimes returns the completed build times in ascending order (tests).
func (e *Estimator) sortedTimes() []int32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []int32
	for _, t := range e.times[:] {
		if t != 0 && t != abandoned {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

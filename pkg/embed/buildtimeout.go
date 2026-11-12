package embed

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/robogg133/gonion/pkg/cbt"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/hs/capi"
)

// testCircuitPort is the port the exits of test circuits must allow.
const testCircuitPort = 443

// unlearnedBuildTimeout is how long a circuit build is waited for until a
// timeout has been learned: gonion's former fixed deadline, rather than the
// spec's 60 s cbtinitialtimeout (which still bounds measurement).
const unlearnedBuildTimeout = 30 * time.Second

// buildTimeoutError is returned when a build passed its soft timeout. It is
// a context.DeadlineExceeded for the caller and path-bias accounting, and
// reports how many hops had opened.
type buildTimeoutError struct {
	hops    int
	timeout time.Duration
}

func (e *buildTimeoutError) Error() string {
	return fmt.Sprintf("circuit build timed out after %v (%d hops open)", e.timeout, e.hops)
}

func (e *buildTimeoutError) Unwrap() error { return context.DeadlineExceeded }

// PathBiasHops reports the open hops for path-bias accounting.
func (e *buildTimeoutError) PathBiasHops() int { return e.hops }

// circuitTimer applies the learned circuit build timeout to builds (path-spec,
// "Learning when to give up on circuit construction"): a build that passes the
// soft timeout is given up by its caller, who builds another circuit, but it
// keeps building as a measurement circuit until the close timeout so the tail
// of the build times is still recorded, and is closed afterwards.
type circuitTimer struct {
	est     *cbt.Estimator
	persist *cbt.Persistence
	obs     *observability

	// lifetime bounds measurement circuits; set once the client exists.
	lifetime atomic.Pointer[context.Context]

	saveMu sync.Mutex
}

func newCircuitTimer(params cbt.Params, persist *cbt.Persistence, obs *observability) *circuitTimer {
	return &circuitTimer{
		est:     cbt.New(params, unlearnedBuildTimeout),
		persist: persist,
		obs:     obs,
	}
}

// load restores a persisted history; a broken one only means relearning.
func (t *circuitTimer) load(ctx context.Context) {
	if t == nil || t.persist == nil || t.persist.Load == nil {
		return
	}
	data, err := t.persist.Load(ctx)
	if err == nil && data != nil {
		err = t.est.Load(data)
	}
	if err != nil {
		t.obs.logf("circuit: build times not restored: %v", err)
	}
}

// save persists the history, if the caller provided storage.
func (t *circuitTimer) save(ctx context.Context) {
	if t == nil || t.persist == nil || t.persist.Save == nil {
		return
	}
	t.saveMu.Lock()
	defer t.saveMu.Unlock()
	data, err := t.est.Marshal()
	if err == nil {
		err = t.persist.Save(ctx, data)
	}
	if err != nil {
		t.obs.logf("circuit: build times not saved: %v", err)
	}
}

// setParams applies the cbt* parameters of the current consensus.
func (t *circuitTimer) setParams(cns *common.Consensus) {
	if t != nil {
		t.est.SetParams(cbt.ParamsFrom(cns))
	}
}

func (t *circuitTimer) lifetimeCtx() context.Context {
	if p := t.lifetime.Load(); p != nil {
		return *p
	}
	return context.Background()
}

// closer is a built circuit; a build returns one exactly when it returns no
// error.
type closer interface{ Close() error }

// timedBuild runs build for a circuit of the given length started at start,
// calling onHop each time a hop opens. It returns the circuit if it opens
// within the soft timeout, and calls release itself whenever it doesn't
// return a circuit (for a measurement circuit, once that ends). A nil timer
// builds without a learned timeout.
func timedBuild[C closer](t *circuitTimer, ctx context.Context, start time.Time, hops int, build func(ctx context.Context, onHop func(hops int)) (C, error), release func()) (C, error) {
	var none C
	if t == nil {
		circ, err := build(ctx, func(int) {})
		if err != nil {
			release()
		}
		return circ, err
	}

	soft, closeTimeout := t.est.Timeouts(hops)
	var opened atomic.Int32
	var thirdHop atomic.Int64 // time to the third hop, 0 before
	onHop := func(n int) {
		opened.Store(int32(n))
		if n == 3 {
			thirdHop.CompareAndSwap(0, int64(max(time.Since(start), 1)))
		}
	}

	// Past the soft timeout the build no longer belongs to the caller: it
	// runs until the close timeout or the client ends.
	buildCtx, cancelBuild := context.WithDeadline(t.lifetimeCtx(), start.Add(closeTimeout))
	type result struct {
		circ C
		err  error
	}
	done := make(chan result, 1)
	go func() {
		circ, err := build(buildCtx, onHop)
		done <- result{circ, err}
	}()

	softTimer := time.NewTimer(time.Until(start.Add(soft)))
	defer softTimer.Stop()
	select {
	case r := <-done:
		closed := buildCtx.Err() != nil
		cancelBuild()
		t.finish(r.err, closed, opened.Load(), thirdHop.Load(), false)
		if r.err != nil {
			release()
		}
		return r.circ, r.err

	case <-ctx.Done():
		// The caller gave up. Its own deadline counts as a timeout (the
		// circuit keeps measuring); a cancellation stops the build.
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			cancelBuild()
			if r := <-done; r.err == nil {
				_ = r.circ.Close()
			}
			release()
			return none, ctx.Err()
		}

	case <-softTimer.C:
	}

	hopsOpen := int(opened.Load())
	if t.est.TimedOut(hopsOpen >= 1) {
		t.obs.logf("circuit: most recent builds timed out, relearning the build timeout")
	}
	go func() {
		r := <-done
		closed := buildCtx.Err() != nil
		cancelBuild()
		t.finish(r.err, closed, opened.Load(), thirdHop.Load(), true)
		if r.err == nil {
			_ = r.circ.Close()
		}
		release()
	}()
	return none, &buildTimeoutError{hops: hopsOpen, timeout: time.Since(start).Round(time.Millisecond)}
}

// finish records a build's outcome: the time to its third hop if it got
// there (also for a measurement circuit, or a longer circuit failing later),
// or an abandoned build if it reached the close timeout after opening its
// first hop (without a first hop the network may be down).
func (t *circuitTimer) finish(err error, closed bool, opened int32, thirdHop int64, timedOut bool) {
	var save bool
	switch {
	case thirdHop > 0:
		save = t.est.Record(time.Duration(thirdHop))
		if !timedOut {
			t.est.Completed()
		}

	case err != nil && closed && opened >= 1:
		save = t.est.Abandoned()
	}
	if save {
		go t.save(context.Background())
	}
}

// buildTimeoutStats are the learned timeout's figures for Stats.
func (t *circuitTimer) stats() cbt.Stats {
	if t == nil {
		return cbt.Stats{}
	}
	return t.est.Stats()
}

// learn builds test circuits while fewer than cbtmincircs build times are
// recorded (path-spec: one every cbttestfreq, at most cbtmaxopencircs at
// once), so a fresh client learns its timeout without waiting for traffic.
// Like C tor's (general purpose circuits), test circuits end at an exit,
// here one allowing port 443, since exit hops build slower than internal
// ones; they are closed once built.
func (c *Client) learn(ctx context.Context) {
	var open atomic.Int32
	for {
		params := c.timer.est.Params()
		select {
		case <-ctx.Done():
			return
		case <-time.After(params.TestFrequency):
		}
		if !c.timer.est.NeedsCircuits() || int(open.Load()) >= params.MaxOpenCircs {
			continue
		}
		cns := c.Consensus()
		if !cns.IsAuthenticated() || !cns.TrustedHydrated() || !cns.IsLive(time.Now()) {
			continue
		}
		c.timer.setParams(cns)
		open.Add(1)
		go func() {
			defer open.Add(-1)
			buildCtx, cancel := context.WithTimeout(ctx, unlearnedBuildTimeout)
			defer cancel()
			circ, _, err := capi.BuildGuardedCircuit(buildCtx, contextBuilder{ctx: buildCtx, lifetime: c.lifetime, builder: c.builder}, cns, c.nextID.Add(1), 3, testCircuitPort, nil, false)
			if err != nil {
				return
			}
			_ = circ.Close()
		}()
	}
}

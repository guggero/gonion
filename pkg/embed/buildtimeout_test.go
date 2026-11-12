package embed

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/cbt"
)

type fakeCirc struct{ closed atomic.Int32 }

func (f *fakeCirc) Close() error {
	f.closed.Add(1)
	return nil
}

// fakeBuild opens hops one per step, honoring ctx, and returns a circuit
// after the last one.
func fakeBuild(circ *fakeCirc, hops int, step time.Duration) func(context.Context, func(int)) (*fakeCirc, error) {
	return func(ctx context.Context, onHop func(int)) (*fakeCirc, error) {
		for n := 1; n <= hops; n++ {
			select {
			case <-time.After(step):
				onHop(n)
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return circ, nil
	}
}

// learnedTimer has learned a soft timeout of 50 ms and closes after 500 ms.
func learnedTimer(t *testing.T) *circuitTimer {
	t.Helper()
	p := cbt.DefaultParams()
	p.InitialTimeout = 500 * time.Millisecond
	timer := newCircuitTimer(p, nil, nil)
	for range 100 {
		timer.est.Record(50 * time.Millisecond)
	}
	if soft, closeTimeout := timer.est.Timeouts(3); soft != 50*time.Millisecond || closeTimeout != 500*time.Millisecond {
		t.Fatalf("soft %v close %v", soft, closeTimeout)
	}
	return timer
}

type releaseCounter struct{ n atomic.Int32 }

func (r *releaseCounter) release() { r.n.Add(1) }

// TestTimedBuildRecordsFastBuilds returns a circuit built in time, keeps
// its connection reference with the caller and records its build time.
func TestTimedBuildRecordsFastBuilds(t *testing.T) {
	timer := learnedTimer(t)
	var released releaseCounter
	circ := &fakeCirc{}
	got, err := timedBuild(timer, context.Background(), time.Now(), 3, fakeBuild(circ, 3, 5*time.Millisecond), released.release)
	if err != nil || got != circ {
		t.Fatalf("got %v %v", got, err)
	}
	if released.n.Load() != 0 || circ.closed.Load() != 0 {
		t.Fatal("built circuit closed or released")
	}
	if st := timer.stats(); st.Observations != 101 {
		t.Fatalf("%d observations", st.Observations)
	}
}

// TestTimedBuildSoftTimeout gives up a slow build at the soft timeout with a
// deadline error carrying the open hops, while the circuit keeps building
// for measurement: its time is recorded, then it is closed and released.
func TestTimedBuildSoftTimeout(t *testing.T) {
	timer := learnedTimer(t)
	var released releaseCounter
	circ := &fakeCirc{}
	start := time.Now()
	_, err := timedBuild(timer, context.Background(), start, 3, fakeBuild(circ, 3, 40*time.Millisecond), released.release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Fatalf("waited %v past a 50ms timeout", elapsed)
	}
	var progress buildTimeoutErrorProgress
	if !errors.As(err, &progress) || progress.PathBiasHops() != 1 {
		t.Fatalf("no hop progress in %v", err)
	}

	waitFor(t, func() bool { return released.n.Load() == 1 })
	if circ.closed.Load() != 1 {
		t.Fatal("measurement circuit not closed")
	}
	if st := timer.stats(); st.Observations != 101 {
		t.Fatalf("measurement not recorded: %d observations", st.Observations)
	}
}

type buildTimeoutErrorProgress interface{ PathBiasHops() int }

// TestTimedBuildAbandoned records a build that reaches the close timeout
// after opening its first hop, but not one that never got a first hop.
func TestTimedBuildAbandoned(t *testing.T) {
	timer := learnedTimer(t)
	var released releaseCounter
	// First hop after 20 ms, then nothing.
	stuck := func(ctx context.Context, onHop func(int)) (*fakeCirc, error) {
		select {
		case <-time.After(20 * time.Millisecond):
			onHop(1)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if _, err := timedBuild(timer, context.Background(), time.Now(), 3, stuck, released.release); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	waitFor(t, func() bool { return released.n.Load() == 1 })
	if st := timer.stats(); st.Abandoned != 1 {
		t.Fatalf("%d abandoned", st.Abandoned)
	}

	// Without a first hop (no network), nothing is recorded.
	offline := func(ctx context.Context, onHop func(int)) (*fakeCirc, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if _, err := timedBuild(timer, context.Background(), time.Now(), 3, offline, released.release); err == nil {
		t.Fatal("offline build succeeded")
	}
	waitFor(t, func() bool { return released.n.Load() == 2 })
	if st := timer.stats(); st.Abandoned != 1 {
		t.Fatalf("offline build recorded: %d abandoned", st.Abandoned)
	}
}

// TestTimedBuildCallerCancel stops the build when the caller cancels, but
// keeps measuring when only the caller's deadline passed.
func TestTimedBuildCallerCancel(t *testing.T) {
	timer := newCircuitTimer(cbt.DefaultParams(), nil, nil) // 30 s soft timeout
	var released releaseCounter
	circ := &fakeCirc{}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	if _, err := timedBuild(timer, ctx, time.Now(), 3, fakeBuild(circ, 3, 50*time.Millisecond), released.release); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if released.n.Load() != 1 {
		t.Fatal("canceled build not released")
	}
	if st := timer.stats(); st.Observations != 0 {
		t.Fatal("canceled build recorded")
	}

	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := timedBuild(timer, ctx, time.Now(), 3, fakeBuild(circ, 3, 20*time.Millisecond), released.release); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	waitFor(t, func() bool { return released.n.Load() == 2 })
	if st := timer.stats(); st.Observations != 1 || circ.closed.Load() != 1 {
		t.Fatalf("measurement after the caller's deadline: %+v closed=%d", st, circ.closed.Load())
	}
}

// TestTimedBuildNilTimer builds without a learned timeout.
func TestTimedBuildNilTimer(t *testing.T) {
	var released releaseCounter
	circ := &fakeCirc{}
	got, err := timedBuild[*fakeCirc](nil, context.Background(), time.Now(), 3, fakeBuild(circ, 3, time.Millisecond), released.release)
	if err != nil || got != circ || released.n.Load() != 0 {
		t.Fatalf("got %v %v released=%d", got, err, released.n.Load())
	}
	boom := errors.New("boom")
	_, err = timedBuild[*fakeCirc](nil, context.Background(), time.Now(), 3, func(context.Context, func(int)) (*fakeCirc, error) { return nil, boom }, released.release)
	if !errors.Is(err, boom) || released.n.Load() != 1 {
		t.Fatalf("got %v released=%d", err, released.n.Load())
	}
}

// TestCircuitTimerPersistence restores a saved history and survives a
// broken one.
func TestCircuitTimerPersistence(t *testing.T) {
	var saved []byte
	persist := &cbt.Persistence{
		Load: func(context.Context) ([]byte, error) { return saved, nil },
		Save: func(_ context.Context, data []byte) error {
			saved = data
			return nil
		},
	}
	timer := newCircuitTimer(cbt.DefaultParams(), persist, nil)
	timer.load(context.Background()) // first run: nothing saved
	for range 120 {
		timer.est.Record(700 * time.Millisecond)
	}
	timer.save(context.Background())

	restored := newCircuitTimer(cbt.DefaultParams(), persist, nil)
	restored.load(context.Background())
	if st := restored.stats(); !st.Learned || st.Observations != 120 {
		t.Fatalf("restored %+v", st)
	}

	saved = []byte("garbage")
	broken := newCircuitTimer(cbt.DefaultParams(), persist, nil)
	broken.load(context.Background())
	if st := broken.stats(); st.Observations != 0 || st.SoftTimeout != unlearnedBuildTimeout {
		t.Fatalf("broken state used: %+v", st)
	}
}

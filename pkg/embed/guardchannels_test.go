package embed

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeConn is a sharedConn whose closing can be observed.
type fakeConn struct {
	ctx    context.Context
	cancel context.CancelFunc
	closes atomic.Int32
}

func newFakeConn() *fakeConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &fakeConn{ctx: ctx, cancel: cancel}
}

func (f *fakeConn) Context() context.Context { return f.ctx }

func (f *fakeConn) Close() error {
	f.closes.Add(1)
	f.cancel()
	return nil
}

func (f *fakeConn) isClosed() bool { return f.closes.Load() > 0 }

// connector counts its dials and hands out fake connections.
type connector struct {
	mu    sync.Mutex
	conns []*fakeConn
	err   error
	delay time.Duration
}

func (c *connector) connect(ctx context.Context) (sharedConn, error) {
	if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	conn := newFakeConn()
	c.conns = append(c.conns, conn)
	return conn, nil
}

func (c *connector) dials() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.conns)
}

func testChannels(idle time.Duration) *guardChannels {
	g := newGuardChannels()
	g.idleTimeout = func() time.Duration { return idle }
	return g
}

var guardA, guardB = [20]byte{1}, [20]byte{2}

// TestGuardChannelsShare builds several circuits over one connection per
// guard, and closes it only after the last circuit is gone and the idle
// timeout passed.
func TestGuardChannelsShare(t *testing.T) {
	g := testChannels(50 * time.Millisecond)
	var c connector
	ctx := context.Background()

	a1, release1, err := g.acquire(ctx, guardA, c.connect)
	if err != nil {
		t.Fatal(err)
	}
	a2, release2, err := g.acquire(ctx, guardA, c.connect)
	if err != nil {
		t.Fatal(err)
	}
	b1, releaseB, err := g.acquire(ctx, guardB, c.connect)
	if err != nil {
		t.Fatal(err)
	}
	if a1 != a2 || a1 == b1 || c.dials() != 2 || g.count() != 2 {
		t.Fatalf("dials=%d channels=%d", c.dials(), g.count())
	}

	// Releasing twice counts once.
	release1()
	release1()
	time.Sleep(100 * time.Millisecond)
	if a1.(*fakeConn).isClosed() {
		t.Fatal("connection closed while a circuit uses it")
	}

	release2()
	if a1.(*fakeConn).isClosed() {
		t.Fatal("connection closed without an idle period")
	}
	waitFor(t, func() bool { return a1.(*fakeConn).isClosed() })
	if g.count() != 1 {
		t.Fatalf("%d channels left", g.count())
	}
	releaseB()
}

// TestGuardChannelsReuseWhileIdle keeps a connection that gets a new circuit
// within the idle timeout.
func TestGuardChannelsReuseWhileIdle(t *testing.T) {
	g := testChannels(80 * time.Millisecond)
	var c connector
	ctx := context.Background()

	first, release, err := g.acquire(ctx, guardA, c.connect)
	if err != nil {
		t.Fatal(err)
	}
	release()
	time.Sleep(20 * time.Millisecond)
	again, release, err := g.acquire(ctx, guardA, c.connect)
	if err != nil {
		t.Fatal(err)
	}
	if again != first || c.dials() != 1 {
		t.Fatal("idle connection not reused")
	}
	time.Sleep(150 * time.Millisecond)
	if first.(*fakeConn).isClosed() {
		t.Fatal("idle timer of a reused connection still ran")
	}
	release()
}

// TestGuardChannelsConcurrentDial shares one dial among concurrent circuits.
func TestGuardChannelsConcurrentDial(t *testing.T) {
	g := testChannels(time.Minute)
	c := connector{delay: 30 * time.Millisecond}
	var wg sync.WaitGroup
	conns := make([]sharedConn, 8)
	for i := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, _, err := g.acquire(context.Background(), guardA, c.connect)
			if err != nil {
				t.Error(err)
			}
			conns[i] = conn
		}()
	}
	wg.Wait()
	if c.dials() != 1 {
		t.Fatalf("%d dials", c.dials())
	}
	for _, conn := range conns {
		if conn != conns[0] {
			t.Fatal("circuits got different connections")
		}
	}
	g.close()
}

// TestGuardChannelsDialFailure reports a failed dial to everyone waiting for
// it and dials again for the next circuit.
func TestGuardChannelsDialFailure(t *testing.T) {
	g := testChannels(time.Minute)
	boom := errors.New("guard unreachable")
	c := connector{err: boom, delay: 20 * time.Millisecond}
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := g.acquire(context.Background(), guardA, c.connect); !errors.Is(err, boom) {
				t.Errorf("got %v", err)
			}
		}()
	}
	wg.Wait()
	if g.count() != 0 {
		t.Fatal("failed channel kept")
	}

	c.mu.Lock()
	c.err = nil
	c.mu.Unlock()
	if _, release, err := g.acquire(context.Background(), guardA, c.connect); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
}

// TestGuardChannelsInitiatorCanceled lets a waiting circuit dial itself when
// the circuit whose dial it waited for gave up.
func TestGuardChannelsInitiatorCanceled(t *testing.T) {
	g := testChannels(time.Minute)
	c := connector{delay: 50 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() {
		_, _, err := g.acquire(ctx, guardA, c.connect)
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)

	waiter := make(chan error)
	go func() {
		_, release, err := g.acquire(context.Background(), guardA, c.connect)
		if err == nil {
			release()
		}
		waiter <- err
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("initiator: %v", err)
	}
	if err := <-waiter; err != nil {
		t.Fatalf("waiter: %v", err)
	}
	if c.dials() != 1 {
		t.Fatalf("%d successful dials", c.dials())
	}
	g.close()
}

// TestGuardChannelsDeadConnection replaces a connection that failed, and
// closes it once its circuits are released.
func TestGuardChannelsDeadConnection(t *testing.T) {
	g := testChannels(time.Minute)
	var c connector
	ctx := context.Background()

	old, releaseOld, err := g.acquire(ctx, guardA, c.connect)
	if err != nil {
		t.Fatal(err)
	}
	old.(*fakeConn).cancel() // link failure
	waitFor(t, func() bool { return g.count() == 0 })

	fresh, releaseFresh, err := g.acquire(ctx, guardA, c.connect)
	if err != nil {
		t.Fatal(err)
	}
	if fresh == old || c.dials() != 2 {
		t.Fatal("dead connection reused")
	}
	releaseOld()
	if !old.(*fakeConn).isClosed() {
		t.Fatal("replaced connection not closed")
	}
	if fresh.(*fakeConn).isClosed() {
		t.Fatal("fresh connection closed")
	}
	releaseFresh()
	g.close()
}

// TestGuardChannelsClose closes every connection, refuses new circuits and
// closes a connection that finishes dialing afterwards.
func TestGuardChannelsClose(t *testing.T) {
	g := testChannels(time.Minute)
	var c connector
	held, release, err := g.acquire(context.Background(), guardA, c.connect)
	if err != nil {
		t.Fatal(err)
	}

	slow := connector{delay: 50 * time.Millisecond}
	dialing := make(chan error)
	go func() {
		_, _, err := g.acquire(context.Background(), guardB, slow.connect)
		dialing <- err
	}()
	time.Sleep(10 * time.Millisecond)

	g.close()
	if !held.(*fakeConn).isClosed() {
		t.Fatal("open connection survived close")
	}
	if err := <-dialing; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial during close: %v", err)
	}
	if slow.dials() != 1 || !slow.conns[0].isClosed() {
		t.Fatal("connection dialed during close not closed")
	}
	if _, _, err := g.acquire(context.Background(), guardA, c.connect); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("acquire after close: %v", err)
	}
	release() // after close: harmless
}

// TestGuardChannelsNil keeps a connection per circuit without a registry.
func TestGuardChannelsNil(t *testing.T) {
	var g *guardChannels
	var c connector
	a, releaseA, err := g.acquire(context.Background(), guardA, c.connect)
	if err != nil {
		t.Fatal(err)
	}
	b, releaseB, err := g.acquire(context.Background(), guardA, c.connect)
	if err != nil {
		t.Fatal(err)
	}
	if a == b || c.dials() != 2 {
		t.Fatal("nil registry shared a connection")
	}
	releaseA()
	if !a.(*fakeConn).isClosed() || b.(*fakeConn).isClosed() {
		t.Fatal("release closed the wrong connection")
	}
	releaseB()
	g.close()
	if g.count() != 0 {
		t.Fatal("nil registry has channels")
	}
}

// TestClientChannelIdleTimeout stays within C tor's 3 to 4.5 minutes.
func TestClientChannelIdleTimeout(t *testing.T) {
	for range 100 {
		d := clientChannelIdleTimeout()
		if d < 180*time.Second || d >= 270*time.Second {
			t.Fatalf("idle timeout %v", d)
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

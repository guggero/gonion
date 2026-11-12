package embed

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net"
	"sync"
	"time"
)

// sharedConn is the part of an OR connection the channel registry needs.
// *gonion.Conn implements it; tests use fakes.
type sharedConn interface {
	// Context is done once the connection is closed or failed.
	Context() context.Context
	Close() error
}

// guardChannels shares one OR connection per first hop among the circuits
// built through it, like C tor's channels: a client keeps one TLS connection
// to its guard and multiplexes its circuits over it. A connection per circuit
// shows up as parallel connections from one address, and relays rate-limit
// circuit creation for clients holding three or more (C tor's
// DoSCircuitCreationMinConnections), which made circuit builds fail.
//
// Every circuit holds a reference to its connection. A connection without
// references is closed after an idle timeout, like C tor's client channels,
// so circuits built shortly after each other share it. A nil *guardChannels
// doesn't share: every acquire connects and every release closes.
type guardChannels struct {
	mu     sync.Mutex
	open   map[[20]byte]*guardChannel
	closed bool

	// idleTimeout returns how long a connection without circuits is kept.
	idleTimeout func() time.Duration
}

// guardChannel is one shared connection, or the dial that will produce it.
type guardChannel struct {
	ready chan struct{} // closed once conn or err is set
	conn  sharedConn
	err   error
	refs  int
	idle  *time.Timer
}

func newGuardChannels() *guardChannels {
	return &guardChannels{
		open:        make(map[[20]byte]*guardChannel),
		idleTimeout: clientChannelIdleTimeout,
	}
}

// clientChannelIdleTimeout is C tor's idle timeout for client channels: 3 to
// 4.5 minutes (channelpadding_get_channel_idle_timeout).
func clientChannelIdleTimeout() time.Duration {
	const base = 180 * time.Second
	n, err := rand.Int(rand.Reader, big.NewInt(int64(base/2)))
	if err != nil {
		return base
	}
	return base + time.Duration(n.Int64())
}

// acquire returns the open connection to the relay with the given identity,
// or connects one with connect. Concurrent callers share one dial. The
// returned release must be called once when the caller (a circuit) no longer
// uses the connection.
func (g *guardChannels) acquire(ctx context.Context, id [20]byte, connect func(context.Context) (sharedConn, error)) (sharedConn, func(), error) {
	if g == nil {
		conn, err := connect(ctx)
		if err != nil {
			return nil, nil, err
		}
		return conn, func() { _ = conn.Close() }, nil
	}

	for {
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			return nil, nil, net.ErrClosed
		}
		ch := g.open[id]
		if ch == nil {
			return g.dial(ctx, id, connect)
		}
		ready := ch.ready
		g.mu.Unlock()

		select {
		case <-ready:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}

		g.mu.Lock()
		switch {
		case g.closed:
			g.mu.Unlock()
			return nil, nil, net.ErrClosed

		case ch.err == nil && ch.conn.Context().Err() == nil && g.open[id] == ch:
			ch.refs++
			if ch.idle != nil {
				ch.idle.Stop()
				ch.idle = nil
			}
			g.mu.Unlock()
			return ch.conn, g.releaser(id, ch), nil
		}
		if g.open[id] == ch {
			delete(g.open, id)
		}
		err := ch.err
		g.mu.Unlock()

		// The dial we waited for failed. Its error is ours too, unless
		// it only failed because its caller gave up: then dial again.
		if err != nil && !errors.Is(err, context.Canceled) &&
			!errors.Is(err, context.DeadlineExceeded) {

			return nil, nil, err
		}
	}
}

// dial connects a new channel; g.mu is held on entry and released.
func (g *guardChannels) dial(ctx context.Context, id [20]byte, connect func(context.Context) (sharedConn, error)) (sharedConn, func(), error) {
	ch := &guardChannel{ready: make(chan struct{})}
	g.open[id] = ch
	g.mu.Unlock()

	conn, err := connect(ctx)

	g.mu.Lock()
	ch.conn, ch.err = conn, err
	close(ch.ready)
	if err != nil || g.closed {
		if g.open[id] == ch {
			delete(g.open, id)
		}
		closed := g.closed
		g.mu.Unlock()
		if err != nil {
			return nil, nil, err
		}
		_ = conn.Close()
		if closed {
			return nil, nil, net.ErrClosed
		}
	}
	ch.refs++
	g.mu.Unlock()

	// A failed connection is forgotten right away, so the next circuit
	// connects anew instead of waiting for the idle timeout.
	context.AfterFunc(conn.Context(), func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.open[id] == ch {
			delete(g.open, id)
		}
		if ch.idle != nil {
			ch.idle.Stop()
			ch.idle = nil
		}
	})
	return conn, g.releaser(id, ch), nil
}

// releaser returns the release function of one reference to ch.
func (g *guardChannels) releaser(id [20]byte, ch *guardChannel) func() {
	var once sync.Once
	return func() {
		once.Do(func() { g.release(id, ch) })
	}
}

func (g *guardChannels) release(id [20]byte, ch *guardChannel) {
	g.mu.Lock()
	ch.refs--
	if ch.refs > 0 {
		g.mu.Unlock()
		return
	}
	if g.open[id] != ch || g.closed {
		// Replaced (it failed) or the registry is closed: nothing will
		// reuse it.
		g.mu.Unlock()
		_ = ch.conn.Close()
		return
	}
	ch.idle = time.AfterFunc(g.idleTimeout(), func() {
		g.mu.Lock()
		if ch.refs > 0 || g.open[id] != ch {
			g.mu.Unlock()
			return
		}
		delete(g.open, id)
		ch.idle = nil
		g.mu.Unlock()
		_ = ch.conn.Close()
	})
	g.mu.Unlock()
}

// count returns the number of open (or connecting) channels.
func (g *guardChannels) count() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.open)
}

// close closes every channel and refuses new ones.
func (g *guardChannels) close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	var conns []sharedConn
	for id, ch := range g.open {
		delete(g.open, id)
		if ch.idle != nil {
			ch.idle.Stop()
			ch.idle = nil
		}
		select {
		case <-ch.ready:
			if ch.err == nil {
				conns = append(conns, ch.conn)
			}
		default:
			// Still dialing: dial closes it once it sees g.closed.
		}
	}
	g.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

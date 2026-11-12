package embed

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil/guardfixture"
)

// deadFallback returns a bootstrap connection carrying a fallback's identity,
// whose far end is closed right away so the link handshake fails.
func deadFallback(id byte) net.Conn {
	a, b := net.Pipe()
	_ = b.Close()
	return pinnedPipe{Conn: a, id: [20]byte{id}}
}

func fastRetries(t *testing.T) {
	t.Helper()
	old := bootstrapRetryDelay
	bootstrapRetryDelay = time.Millisecond
	t.Cleanup(func() { bootstrapRetryDelay = old })
}

// TestBootstrapRetriesAnotherFallback checks that a failed bootstrap is
// retried on another fallback, up to BootstrapAttempts times, and that a
// fallback that already failed is skipped.
func TestBootstrapRetriesAnotherFallback(t *testing.T) {
	fastRetries(t)

	// The dialer offers fallback 1 twice in a row; the repeat is skipped.
	offered := []byte{1, 1, 2, 3, 4}
	var used []byte
	opts := DefaultOptions()
	opts.Guards = guardfixture.Manager(t)
	opts.ORDialer = func(context.Context) (net.Conn, error) {
		id := offered[0]
		offered = offered[1:]
		used = append(used, id)
		return deadFallback(id), nil
	}

	_, err := New(context.Background(), opts)
	if err == nil {
		t.Fatal("bootstrap over dead fallbacks succeeded")
	}
	if got := string(used); got != string([]byte{1, 1, 2, 3}) {
		t.Fatalf("dialed %v", used)
	}
}

// TestBootstrapSingleAttempt keeps the former behaviour for Options that
// don't set BootstrapAttempts.
func TestBootstrapSingleAttempt(t *testing.T) {
	fastRetries(t)
	dials := 0
	opts := Options{Guards: guardfixture.Manager(t)}
	opts.ORDialer = func(context.Context) (net.Conn, error) {
		dials++
		return deadFallback(byte(dials)), nil
	}
	if _, err := New(context.Background(), opts); err == nil || dials != 1 {
		t.Fatalf("err=%v dials=%d", err, dials)
	}
}

// TestBootstrapPermanentErrorNotRetried stops at a configuration error that
// another fallback can't fix.
func TestBootstrapPermanentErrorNotRetried(t *testing.T) {
	fastRetries(t)
	dials := 0
	opts := DefaultOptions()
	opts.Guards = guardfixture.Manager(t)
	opts.ORDialer = func(context.Context) (net.Conn, error) {
		dials++
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil // no identity pin
	}
	_, err := New(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "identity is required") ||
		dials != 1 {

		t.Fatalf("err=%v dials=%d", err, dials)
	}
}

// TestBootstrapRetryHonorsContext stops retrying once the context is done.
func TestBootstrapRetryHonorsContext(t *testing.T) {
	old := bootstrapRetryDelay
	bootstrapRetryDelay = time.Hour
	t.Cleanup(func() { bootstrapRetryDelay = old })

	ctx, cancel := context.WithCancel(context.Background())
	dials := 0
	opts := DefaultOptions()
	opts.Guards = guardfixture.Manager(t)
	opts.ORDialer = func(context.Context) (net.Conn, error) {
		dials++
		cancel() // the next attempt would wait an hour
		return deadFallback(byte(dials)), nil
	}
	_, err := New(ctx, opts)
	if !errors.Is(err, context.Canceled) || dials != 1 {
		t.Fatalf("err=%v dials=%d", err, dials)
	}
}

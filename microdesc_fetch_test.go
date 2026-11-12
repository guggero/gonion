package gonion

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

// fakeDigests returns n distinct digest strings and the indices of all of them.
func fakeDigests(n int) ([]string, []int) {
	digests := make([]string, n)
	need := make([]int, n)
	for i := range digests {
		digests[i] = fmt.Sprintf("d%04d", i)
		need[i] = i
	}
	return digests, need
}

// TestFetchMicrodescriptorsConcurrent checks that every requested descriptor
// lands at its own index, that batches respect the size limit, and that
// several (but at most microdescFetchParallelism) requests run at once.
func TestFetchMicrodescriptorsConcurrent(t *testing.T) {
	digests, need := fakeDigests(microdescBatchSize*8 + 7)
	// Skip a few, as if they came from the cache.
	need = append(need[:10:10], need[20:]...)
	descriptors := make([]*common.Microdesc, len(digests))

	var inFlight, peak atomic.Int32
	var mu sync.Mutex
	requested := make(map[string]int)
	fetch := func(want []string) ([]*common.Microdesc, error) {
		if len(want) == 0 || len(want) > microdescBatchSize {
			return nil, fmt.Errorf("batch of %d", len(want))
		}
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)

		out := make([]*common.Microdesc, len(want))
		mu.Lock()
		for i, d := range want {
			requested[d]++
			out[i] = &common.Microdesc{RawDocument: []byte(d)}
		}
		mu.Unlock()
		return out, nil
	}

	err := fetchMicrodescriptors(context.Background(), digests, need, descriptors, fetch)
	if err != nil {
		t.Fatal(err)
	}
	for i, md := range descriptors {
		skipped := i >= 10 && i < 20
		switch {
		case skipped && md != nil:
			t.Fatalf("descriptor %d fetched although not needed", i)
		case !skipped && (md == nil || string(md.RawDocument) != digests[i]):
			t.Fatalf("descriptor %d wrong: %v", i, md)
		case !skipped && requested[digests[i]] != 1:
			t.Fatalf("digest %d requested %d times", i, requested[digests[i]])
		}
	}
	if p := peak.Load(); p < 2 || p > microdescFetchParallelism {
		t.Fatalf("peak concurrency %d", p)
	}
}

// TestFetchMicrodescriptorsStopsOnError checks that the first error is
// returned and no new batch starts after it.
func TestFetchMicrodescriptorsStopsOnError(t *testing.T) {
	digests, need := fakeDigests(microdescBatchSize * 10)
	descriptors := make([]*common.Microdesc, len(digests))
	boom := errors.New("relay closed the stream")
	var calls atomic.Int32
	fetch := func(want []string) ([]*common.Microdesc, error) {
		if calls.Add(1) == 3 {
			return nil, boom
		}
		time.Sleep(2 * time.Millisecond)
		return make([]*common.Microdesc, len(want)), nil
	}
	err := fetchMicrodescriptors(context.Background(), digests, need, descriptors, fetch)
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	// The batches already running finish; nothing new starts.
	if n := calls.Load(); n > 3+microdescFetchParallelism {
		t.Fatalf("%d requests after the error", n)
	}
}

// TestFetchMicrodescriptorsCountMismatch rejects a short response.
func TestFetchMicrodescriptorsCountMismatch(t *testing.T) {
	digests, need := fakeDigests(5)
	descriptors := make([]*common.Microdesc, len(digests))
	fetch := func(want []string) ([]*common.Microdesc, error) {
		return make([]*common.Microdesc, len(want)-1), nil
	}
	err := fetchMicrodescriptors(context.Background(), digests, need, descriptors, fetch)
	if !errors.Is(err, ErrDirectory) {
		t.Fatalf("got %v", err)
	}
}

// TestFetchMicrodescriptorsCanceled stops when the context is done.
func TestFetchMicrodescriptorsCanceled(t *testing.T) {
	digests, need := fakeDigests(microdescBatchSize * 10)
	descriptors := make([]*common.Microdesc, len(digests))
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	fetch := func(want []string) ([]*common.Microdesc, error) {
		calls.Add(1)
		cancel()
		return make([]*common.Microdesc, len(want)), nil
	}
	err := fetchMicrodescriptors(ctx, digests, need, descriptors, fetch)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if n := calls.Load(); n > microdescFetchParallelism {
		t.Fatalf("%d requests after cancel", n)
	}

	// Nothing needed: no request, no error.
	if err := fetchMicrodescriptors(context.Background(), digests, nil, descriptors, fetch); err != nil {
		t.Fatal(err)
	}
}

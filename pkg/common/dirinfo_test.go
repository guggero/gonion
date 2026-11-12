package common_test

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/common"
)

// withoutDescriptorOf returns the signed test consensus's descriptors minus
// the one of the named relay. The test network has six relays with equal
// bandwidth and weights: relay0 and relay1 are guards, relay2 and relay3
// middles, relay4 and relay5 exits.
func withoutDescriptorOf(t *testing.T, c *common.Consensus, nickname string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte, len(c.Microdescriptors))
	for digest, raw := range c.Microdescriptors {
		out[digest] = raw
	}
	for _, r := range c.Trusted().RelayInformation {
		if r.Nickname == nickname {
			delete(out, r.MicrodescriptorDigest)
			return out
		}
	}
	t.Fatalf("no relay %s", nickname)
	return nil
}

// TestHydrationToleratesMissingDescriptor leaves a relay without descriptor
// unloaded instead of failing, while enough of the network is covered.
func TestHydrationToleratesMissingDescriptor(t *testing.T) {
	c := testutil.Consensus(t, time.Now())
	hydrated, err := c.OwnAuthenticatedHydration(withoutDescriptorOf(t, c, "relay2"))
	if err != nil {
		t.Fatal(err)
	}
	if !hydrated.TrustedHydrated() {
		t.Fatal("not marked hydrated")
	}
	for _, r := range hydrated.RelayInformation {
		loaded := r.Nickname != "relay2"
		if r.MicrodescriptorLoaded != loaded || (r.NTorOnionKey != nil) != loaded {
			t.Fatalf("%s loaded=%v key=%v", r.Nickname,
				r.MicrodescriptorLoaded, r.NTorOnionKey != nil)
		}
	}
	// Without one of two middles, 5/6 of the middle bandwidth is loaded.
	if f := hydrated.DirInfoFraction(); math.Abs(f-5.0/6) > 1e-9 {
		t.Fatalf("fraction %v", f)
	}
}

// TestHydrationNeedsEnoughDirInfo refuses a consensus whose descriptors
// cover less than min_paths_for_circs_pct of the paths: withholding
// descriptors must not steer a client to the relays it still knows.
func TestHydrationNeedsEnoughDirInfo(t *testing.T) {
	c := testutil.Consensus(t, time.Now())
	// One of two guards is half of the guard position: 0.5 * 5/6 < 0.6.
	_, err := c.OwnAuthenticatedHydration(withoutDescriptorOf(t, c, "relay0"))
	if err == nil || !strings.Contains(err.Error(), "not enough directory information") {
		t.Fatalf("got %v", err)
	}
	if _, err := c.OwnAuthenticatedHydration(nil); err == nil {
		t.Fatal("hydrated without any descriptor")
	}
}

func relay(bw uint32, loaded bool, flags ...uint8) common.RouterStatus {
	r := common.RouterStatus{BandWidth: bw, MicrodescriptorLoaded: loaded}
	r.StatusFlags[common.FLAG_RUNNING] = true
	r.StatusFlags[common.FLAG_VALID] = true
	for _, f := range flags {
		r.StatusFlags[f] = true
	}
	return r
}

// TestDirInfoFraction checks the path-spec fraction: bandwidth weighted per
// position, relay counts without weighted bandwidth, the middle share without
// exits, and only running, valid, non-BadExit exits.
func TestDirInfoFraction(t *testing.T) {
	weights := common.BandWidthWeight{
		Wgg: 10000, Wgd: 10000, Wmg: 5000, Wmm: 10000, Wme: 0, Wmd: 0,
		Wee: 10000, Wed: 10000,
	}
	notRunning := relay(1000, false, common.FLAG_GUARD)
	notRunning.StatusFlags[common.FLAG_RUNNING] = false
	c := &common.Consensus{
		BandWidthWeight: weights,
		RelayInformation: []common.RouterStatus{
			relay(3000, true, common.FLAG_GUARD),
			relay(1000, false, common.FLAG_GUARD),
			relay(2000, true),
			relay(2000, false),
			relay(1000, true, common.FLAG_EXIT),
			relay(3000, false, common.FLAG_EXIT),
			relay(9000, false, common.FLAG_EXIT, common.FLAG_BAD_EXIT),
			notRunning,
		},
	}
	// Guard: 3000/4000. Middle: guards at Wmg (half), exits at Wme (0),
	// the BadExit as an ordinary relay at Wmm:
	// (1500+2000)/(1500+500+2000+2000+9000) = 3500/15000. Exit: 1000/4000,
	// the BadExit doesn't count.
	want := 0.75 * (3500.0 / 15000) * 0.25
	if f := c.DirInfoFraction(); math.Abs(f-want) > 1e-9 {
		t.Fatalf("fraction %v, want %v", f, want)
	}

	// Without weighted bandwidth, relays are counted.
	c.BandWidthWeight = common.BandWidthWeight{}
	want = 0.5 * (3.0 / 7) * (1.0 / 2)
	if f := c.DirInfoFraction(); math.Abs(f-want) > 1e-9 {
		t.Fatalf("unweighted fraction %v, want %v", f, want)
	}

	// Without exits, the middle share stands in for the exit share.
	c.BandWidthWeight = weights
	c.RelayInformation = c.RelayInformation[:4]
	middle := (1500.0 + 2000) / (1500 + 500 + 2000 + 2000)
	want = 0.75 * middle * middle
	if f := c.DirInfoFraction(); math.Abs(f-want) > 1e-9 {
		t.Fatalf("no-exit fraction %v, want %v", f, want)
	}
}

// TestMinPathsForCircuits reads min_paths_for_circs_pct within param-spec's
// bounds.
func TestMinPathsForCircuits(t *testing.T) {
	for param, want := range map[int32]float64{0: 0.25, 80: 0.8, 99: 0.95} {
		c := &common.Consensus{Params: map[string]int32{"min_paths_for_circs_pct": param}}
		if got := c.MinPathsForCircuits(); math.Abs(got-want) > 1e-9 {
			t.Fatalf("param %d: %v", param, got)
		}
	}
	if got := (&common.Consensus{}).MinPathsForCircuits(); got != 0.6 {
		t.Fatalf("default %v", got)
	}
}

package gonion

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/robogg133/gonion/internal/testutil"
	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/parsers/microdesc"
)

// hydrateSigned hydrates a signed test consensus from its own descriptors.
func hydrateSigned(t *testing.T, signed *common.Consensus) (*common.Consensus, error) {
	t.Helper()
	fetch := func(ds []string) ([]*common.Microdesc, error) {
		out := make([]*common.Microdesc, len(ds))
		for i, digest := range ds {
			parsed, err := (microdesc.Parser{}).Parse(bytes.NewReader(signed.Microdescriptors[digest]), []string{digest})
			if err != nil {
				return nil, err
			}
			out[i] = parsed[0]
		}
		return out, nil
	}
	return hydrateConsensus(context.Background(), signed.Trusted(), nil, fetch)
}

func setReleaseDate(t *testing.T, d time.Time) {
	t.Helper()
	old := ProtocolsReleaseDate
	ProtocolsReleaseDate = d
	t.Cleanup(func() { ProtocolsReleaseDate = old })
}

// TestRequiredClientProtocols applies tor-spec's rules: a consensus newer
// than the release date that requires a missing capability is refused; an
// older one, and missing recommended capabilities, only warn.
func TestRequiredClientProtocols(t *testing.T) {
	now := time.Now().UTC()

	// Today's network: everything required is supported, some recommended
	// capabilities (congestion control, ntor v3) aren't.
	signed := testutil.ConsensusWithProtocols(t, now,
		"Cons=2 Desc=2 FlowCtrl=1 Link=4 Microdesc=2 Relay=2",
		"Cons=2 Desc=2-4 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2-3 Relay=2-6")
	if got := signed.Trusted().RequiredClientProtocols; got != "Cons=2 Desc=2 FlowCtrl=1 Link=4 Microdesc=2 Relay=2" {
		t.Fatalf("required protocols %q", got)
	}
	setReleaseDate(t, now.Add(-24*time.Hour))
	if _, err := hydrateSigned(t, signed); err != nil {
		t.Fatalf("supported protocols refused: %v", err)
	}

	// The network requires ntor v3 (Relay=4).
	signed = testutil.ConsensusWithProtocols(t, now, "Link=4 Relay=2,4", "")
	_, err := hydrateSigned(t, signed)
	if !errors.Is(err, ErrObsoleteProtocols) {
		t.Fatalf("missing required protocol: %v", err)
	}

	// The same consensus from before the release date only warns.
	setReleaseDate(t, now.Add(24*time.Hour))
	if _, err := hydrateSigned(t, signed); err != nil {
		t.Fatalf("consensus older than the release refused: %v", err)
	}
}

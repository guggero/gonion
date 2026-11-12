package gonion

import (
	"context"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

// ProtocolsReleaseDate is when this version's client protocols were last
// reviewed against the network. tor-spec: a client lacking a capability the
// consensus requires must not connect if the consensus is newer than the
// software's release date ("safe forward shutdown" of zombie clients); an
// older consensus only earns a warning. Move it forward with every release.
var ProtocolsReleaseDate = time.Date(2026, time.November, 12, 0, 0, 0, 0, time.UTC)

// checkClientProtocols applies tor-spec's rules for the consensus client
// protocol lists to an authenticated consensus: a missing required
// capability fails with ErrObsoleteProtocols (or warns, for a consensus
// older than ProtocolsReleaseDate), a missing recommended one warns.
func checkClientProtocols(ctx context.Context, c *common.Consensus) error {
	required, err := common.ParseProtocolSet(c.RequiredClientProtocols)
	if err != nil {
		return Public(ErrDirectory, "invalid required-client-protocols")
	}
	if missing := required.Missing(common.ClientProtocols); len(missing) != 0 {
		if c.ValidAfter.After(ProtocolsReleaseDate) {
			return Publicf(ErrObsoleteProtocols, "the network requires client protocols %s", missing)
		}
		logger(ctx).Warn().Str("missing", missing.String()).
			Msg("client is obsolete: the consensus requires protocols it lacks")
	}

	recommended, err := common.ParseProtocolSet(c.RecommendedClientProtocols)
	if err != nil {
		return Public(ErrDirectory, "invalid recommended-client-protocols")
	}
	if missing := recommended.Missing(common.ClientProtocols); len(missing) != 0 {
		logger(ctx).Warn().Str("missing", missing.String()).
			Msg("client is obsolete: the consensus recommends protocols it lacks")
	}
	return nil
}

package path

import "github.com/robogg133/gonion/pkg/common"

func middleWeightFunc(flags [15]bool, weights common.BandWidthWeight) int64 {
	return common.MiddlePositionWeight(flags, weights)
}

// middleValideFunc accepts Fast relays with keys (path-spec: no relay without
// the Fast flag in any non-testing circuit).
func middleValideFunc(r common.RouterStatus) bool {
	return haveAllKeys(&r) && r.StatusFlags[common.FLAG_FAST]
}

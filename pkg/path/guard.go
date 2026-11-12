package path

import "github.com/robogg133/gonion/pkg/common"

func guardWeightFunc(flags [15]bool, weights common.BandWidthWeight) int64 {
	return common.GuardPositionWeight(flags, weights)
}

func guardValideFunc(r common.RouterStatus) bool {
	if !haveAllKeys(&r) {
		return false
	}

	return r.StatusFlags[common.FLAG_GUARD] && r.StatusFlags[common.FLAG_FAST] && r.StatusFlags[common.FLAG_STABLE] && r.StatusFlags[common.FLAG_V2DIR]
}

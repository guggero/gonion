package path

import (
	"github.com/robogg133/gonion/pkg/common"
)

func exitWeightFunc(flags [15]bool, weights common.BandWidthWeight) int64 {
	return common.ExitPositionWeight(flags, weights)
}

func exitValidateFunc(r common.RouterStatus) bool {
	if !haveAllKeys(&r) {
		return false
	}
	if !r.StatusFlags[common.FLAG_EXIT] || r.StatusFlags[common.FLAG_BAD_EXIT] {
		return false
	}
	// path-spec: no relay without the Fast flag in any non-testing circuit.
	return r.StatusFlags[common.FLAG_FAST]
}

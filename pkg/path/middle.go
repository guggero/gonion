package path

import "github.com/robogg133/gonion/pkg/common"

func middleWeightFunc(flags [15]bool, weights common.BandWidthWeight) int64 {
	return common.MiddlePositionWeight(flags, weights)
}

func middleValideFunc(r common.RouterStatus) bool {
	return haveAllKeys(&r)
}

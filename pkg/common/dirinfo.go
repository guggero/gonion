package common

import "math/big"

// GuardPositionWeight is the bandwidth weight (dir-spec, "bandwidth-weights")
// of a relay with the given flags in the guard position.
func GuardPositionWeight(flags [FLAG_ARRAY_LENGTH + 1]bool, w BandWidthWeight) int64 {
	if flags[FLAG_EXIT] && !flags[FLAG_BAD_EXIT] {
		return int64(w.Wgd)
	}
	return int64(w.Wgg)
}

// MiddlePositionWeight is the bandwidth weight of a relay with the given flags
// in a middle position.
func MiddlePositionWeight(flags [FLAG_ARRAY_LENGTH + 1]bool, w BandWidthWeight) int64 {
	exit := flags[FLAG_EXIT] && !flags[FLAG_BAD_EXIT]
	switch {
	case flags[FLAG_GUARD] && exit:
		return int64(w.Wmd)
	case flags[FLAG_GUARD]:
		return int64(w.Wmg)
	case exit:
		return int64(w.Wme)
	default:
		return int64(w.Wmm)
	}
}

// ExitPositionWeight is the bandwidth weight of a relay with the given flags
// in the exit position.
func ExitPositionWeight(flags [FLAG_ARRAY_LENGTH + 1]bool, w BandWidthWeight) int64 {
	if flags[FLAG_GUARD] {
		return int64(w.Wed)
	}
	return int64(w.Wee)
}

// positionFraction is the share of a position's weighted bandwidth (or, if
// that is zero, of its relays) whose descriptor is loaded.
type positionFraction struct {
	have, total        big.Int
	haveRelays, relays int64
}

func (p *positionFraction) add(r *RouterStatus, weight int64) {
	p.relays++
	bw := new(big.Int).Mul(big.NewInt(int64(r.BandWidth)), big.NewInt(max(weight, 0)))
	p.total.Add(&p.total, bw)
	if r.MicrodescriptorLoaded {
		p.haveRelays++
		p.have.Add(&p.have, bw)
	}
}

func (p *positionFraction) value() float64 {
	if p.total.Sign() > 0 {
		f, _ := new(big.Rat).SetFrac(&p.have, &p.total).Float64()
		return f
	}
	if p.relays == 0 {
		return 0
	}
	return float64(p.haveRelays) / float64(p.relays)
}

// DirInfoFraction is the fraction of bandwidth-weighted paths this consensus
// can build with the descriptors it has loaded (path-spec, "We don't build
// circuits until we have enough directory info"): the product of the loaded
// share of the Guard-flagged relays weighted for the guard position, of all
// relays weighted for the middle position and of the Exit-flagged relays
// weighted for the exit position. A position without weighted bandwidth
// counts relays instead, and without exits the middle share stands in for
// the exit share. Only running, valid relays are counted.
func (c *Consensus) DirInfoFraction() float64 {
	var guard, middle, exit positionFraction
	for i := range c.RelayInformation {
		r := &c.RelayInformation[i]
		if !r.StatusFlags[FLAG_RUNNING] || !r.StatusFlags[FLAG_VALID] {
			continue
		}
		middle.add(r, MiddlePositionWeight(r.StatusFlags, c.BandWidthWeight))
		if r.StatusFlags[FLAG_GUARD] {
			guard.add(r, GuardPositionWeight(r.StatusFlags, c.BandWidthWeight))
		}
		if r.StatusFlags[FLAG_EXIT] && !r.StatusFlags[FLAG_BAD_EXIT] {
			exit.add(r, ExitPositionWeight(r.StatusFlags, c.BandWidthWeight))
		}
	}
	exitShare := exit.value()
	if exit.relays == 0 {
		exitShare = middle.value()
	}
	return guard.value() * middle.value() * exitShare
}

// MinPathsForCircuits is the fraction of bandwidth-weighted paths a client
// needs descriptors for before building circuits: the min_paths_for_circs_pct
// consensus parameter (param-spec: 25 to 95, default 60 percent).
func (c *Consensus) MinPathsForCircuits() float64 {
	return float64(c.Parameter("min_paths_for_circs_pct", 60, 25, 95)) / 100
}

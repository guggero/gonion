package common

import (
	"fmt"
	"math/bits"
	"slices"
	"strconv"
	"strings"
)

// ProtocolSet holds subprotocol capabilities (tor-spec, "Subprotocol-based
// versioning"): a bit per supported capability number (0 to 63) for each
// subprotocol name.
type ProtocolSet map[string]uint64

// maxProtocolCapability is the highest capability number dir-spec allows in a
// protocol list.
const maxProtocolCapability = 63

// ClientProtocols are the client subprotocol capabilities gonion implements:
//
//   - Cons=1-2: consensus methods with ed25519 keys in microdescriptors.
//   - Desc=1-3: (bridge) server descriptors with ed25519 cross-signing and
//     without TAP onion keys; not 4, family certificates are rejected.
//   - DirCache=1: plain directory documents, no consensus diffs.
//   - FlowCtrl=1: authenticated circuit SENDMEs, no congestion control.
//   - HSDir=2, HSIntro=4, HSRend=2: v3 onion services.
//   - Link=4-5: link protocols with 4-byte circuit IDs.
//   - Microdesc=1-3: microdescriptors with ed25519 keys, with or without a
//     TAP onion key.
//   - Relay=2: ntor and EXTEND2; no IPv6 extends, ntor v3 or CGO.
var ClientProtocols = mustParseProtocolSet(
	"Cons=1-2 Desc=1-3 DirCache=1 FlowCtrl=1 HSDir=2 HSIntro=4 HSRend=2 " +
		"Link=4-5 Microdesc=1-3 Relay=2",
)

func mustParseProtocolSet(s string) ProtocolSet {
	p, err := ParseProtocolSet(s)
	if err != nil {
		panic(err)
	}
	return p
}

// ParseProtocolSet parses a protocol list like "Cons=2 Desc=2-4 Link=1-3,5"
// (dir-spec "proto" and the consensus protocol lists).
func ParseProtocolSet(s string) (ProtocolSet, error) {
	p := make(ProtocolSet)
	for _, entry := range strings.Fields(s) {
		name, values, ok := strings.Cut(entry, "=")
		if !ok || !validProtocolName(name) {
			return nil, fmt.Errorf("protocols: invalid entry %q", entry)
		}
		if _, dup := p[name]; dup {
			return nil, fmt.Errorf("protocols: duplicate %s", name)
		}
		var set uint64
		if values != "" {
			for item := range strings.SplitSeq(values, ",") {
				a, b, isRange := strings.Cut(item, "-")
				lo, err := strconv.ParseUint(a, 10, 8)
				if err != nil || lo > maxProtocolCapability {
					return nil, fmt.Errorf("protocols: invalid capability %q", item)
				}
				hi := lo
				if isRange {
					hi, err = strconv.ParseUint(b, 10, 8)
					if err != nil || hi < lo || hi > maxProtocolCapability {
						return nil, fmt.Errorf("protocols: invalid range %q", item)
					}
				}
				for n := lo; n <= hi; n++ {
					set |= 1 << n
				}
			}
		}
		p[name] = set
	}
	return p, nil
}

func validProtocolName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// Missing returns the capabilities of p that have doesn't support (each
// capability is a single flag: supporting 5 doesn't imply supporting 4).
func (p ProtocolSet) Missing(have ProtocolSet) ProtocolSet {
	missing := make(ProtocolSet)
	for name, set := range p {
		if lacking := set &^ have[name]; lacking != 0 {
			missing[name] = lacking
		}
	}
	return missing
}

// String renders the set in its canonical form: names sorted, capabilities
// as ascending ranges ("Desc=2-4 Link=1-3,5").
func (p ProtocolSet) String() string {
	names := make([]string, 0, len(p))
	for name := range p {
		names = append(names, name)
	}
	slices.Sort(names)
	var sb strings.Builder
	for i, name := range names {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(name)
		sb.WriteByte('=')
		set, first := p[name], true
		for set != 0 {
			lo := bits.TrailingZeros64(set)
			hi := lo
			for hi < maxProtocolCapability && set&(1<<(hi+1)) != 0 {
				hi++
			}
			if !first {
				sb.WriteByte(',')
			}
			first = false
			if lo == hi {
				sb.WriteString(strconv.Itoa(lo))
			} else {
				fmt.Fprintf(&sb, "%d-%d", lo, hi)
			}
			set &^= (uint64(1)<<(hi-lo+1) - 1) << lo
		}
	}
	return sb.String()
}

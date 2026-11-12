package common

import (
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// PortRange is an inclusive range of ports.
type PortRange struct {
	Lo, Hi uint16
}

// Ports is the set of ports an exit policy summary accepts. It keeps sorted,
// non-overlapping and non-adjacent ranges instead of a bit per port, so a
// relay that accepts nothing costs nothing and a typical exit a few dozen
// ranges. The zero value accepts no port.
//
// A Ports value never modifies its ranges in place: every change builds a new
// slice. Copies of a RouterStatus (and of a whole Consensus) can therefore
// share the ranges safely.
type Ports struct {
	ranges []PortRange
}

// IsAllowed returns true if port n is accepted.
func (p *Ports) IsAllowed(n uint16) bool {
	i := sort.Search(len(p.ranges), func(i int) bool {
		return p.ranges[i].Hi >= n
	})
	return i < len(p.ranges) && p.ranges[i].Lo <= n
}

// SetPort accepts or rejects a single port.
func (p *Ports) SetPort(n uint16, on bool) {
	p.setRange(n, n, on)
}

// Ranges returns a copy of the accepted ranges, in ascending order.
func (p *Ports) Ranges() []PortRange {
	return slices.Clone(p.ranges)
}

// setRange accepts or rejects every port from lo to hi (inclusive).
func (p *Ports) setRange(lo, hi uint16, on bool) {
	if lo > hi {
		return
	}

	var out []PortRange
	for _, r := range p.ranges {
		if r.Hi < lo || r.Lo > hi {
			out = append(out, r)
			continue
		}
		if r.Lo < lo {
			out = append(out, PortRange{Lo: r.Lo, Hi: lo - 1})
		}
		if r.Hi > hi {
			out = append(out, PortRange{Lo: hi + 1, Hi: r.Hi})
		}
	}
	if on {
		out = append(out, PortRange{Lo: lo, Hi: hi})
	}
	p.ranges = normalizeRanges(out)
}

// normalizeRanges sorts the ranges and merges overlapping or adjacent ones.
// It returns nil for no ranges, so equal sets compare equal.
func normalizeRanges(ranges []PortRange) []PortRange {
	if len(ranges) == 0 {
		return nil
	}
	slices.SortFunc(ranges, func(a, b PortRange) int {
		return int(a.Lo) - int(b.Lo)
	})
	out := ranges[:1]
	for _, r := range ranges[1:] {
		last := &out[len(out)-1]
		if int(r.Lo) <= int(last.Hi)+1 {
			last.Hi = max(last.Hi, r.Hi)
			continue
		}
		out = append(out, r)
	}
	return out
}

func (p *Ports) turnOnAllPorts() {
	p.ranges = []PortRange{{Lo: 0, Hi: 65535}}
}

// String renders the accepted ranges as a comma separated list, like
// "22,80-81,443" (empty if no port is accepted). ParsePortRanges reverses it.
func (p *Ports) String() string {
	var sb strings.Builder
	for i, r := range p.ranges {
		if i > 0 {
			sb.WriteByte(',')
		}
		if r.Lo == r.Hi {
			sb.WriteString(strconv.Itoa(int(r.Lo)))
		} else {
			fmt.Fprintf(&sb, "%d-%d", r.Lo, r.Hi)
		}
	}
	return sb.String()
}

// ParsePortRanges parses the output of Ports.String.
func ParsePortRanges(s string) (Ports, error) {
	var p Ports
	if s == "" {
		return p, nil
	}
	var ranges []PortRange
	for item := range strings.SplitSeq(s, ",") {
		lo, hi, err := parsePortItem(item)
		if err != nil {
			return Ports{}, err
		}
		ranges = append(ranges, PortRange{Lo: lo, Hi: hi})
	}
	p.ranges = normalizeRanges(ranges)
	return p, nil
}

// PortsFromBitmap converts the bit-per-port representation older versions
// stored (bit n%8 of byte n/8 set for an accepted port n).
func PortsFromBitmap(b []byte) (Ports, error) {
	var p Ports
	if len(b) != 65536/8 {
		return p, fmt.Errorf("invalid ports bitmap length %d", len(b))
	}
	var ranges []PortRange
	start := -1
	for n := 0; n <= 65536; n++ {
		on := n < 65536 && b[n/8]&(1<<(n%8)) != 0
		switch {
		case on && start < 0:
			start = n
		case !on && start >= 0:
			ranges = append(ranges, PortRange{
				Lo: uint16(start), Hi: uint16(n - 1),
			})
			start = -1
		}
	}
	p.ranges = normalizeRanges(ranges)
	return p, nil
}

// parsePortItem parses "n" or "lo-hi".
func parsePortItem(item string) (uint16, uint16, error) {
	a, b, isRange := strings.Cut(item, "-")
	lo, err := strconv.ParseUint(a, 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port %q", item)
	}
	hi := lo
	if isRange {
		hi, err = strconv.ParseUint(b, 10, 16)
		if err != nil || hi < lo {
			return 0, 0, fmt.Errorf("invalid port range %q", item)
		}
	}
	return uint16(lo), uint16(hi), nil
}

// parsePortList applies every port or range of a policy summary list.
func parsePortList(p *Ports, s string, on bool) error {
	for item := range strings.SplitSeq(s, ",") {
		lo, hi, err := parsePortItem(item)
		if err != nil {
			return err
		}
		p.setRange(lo, hi, on)
	}
	return nil
}

func parseReject(s string) (Ports, error) {
	var p Ports
	p.turnOnAllPorts()
	if err := parsePortList(&p, s, false); err != nil {
		return Ports{}, err
	}
	return p, nil
}

func parseAccept(s string) (Ports, error) {
	var p Ports
	if err := parsePortList(&p, s, true); err != nil {
		return Ports{}, err
	}
	return p, nil
}

// ParsePortsLine parses a "reject/accept" policy line, e.g. "accept 20-21,23".
func ParsePortsLine(dst *Ports, s string) error {
	separated := strings.Split(s, " ")
	if len(separated) != 2 || (separated[0] != "accept" && separated[0] != "reject") {
		return fmt.Errorf("invalid port policy %q", s)
	}

	if separated[0] == "reject" && separated[1] == "1-65535" {
		*dst = Ports{}
		return nil
	} else if separated[0] == "accept" && separated[1] == "1-65535" {
		dst.turnOnAllPorts()
		return nil
	}

	switch separated[0] {
	case "reject":
		p, err := parseReject(separated[1])
		if err != nil {
			return err
		}
		*dst = p
	case "accept":
		p, err := parseAccept(separated[1])
		if err != nil {
			return err
		}
		*dst = p
	}
	return nil
}

// FormatPortsPolicy renders a Ports value back into a policy line
// (the part after "p ").
func FormatPortsPolicy(p *Ports) string {
	switch {
	case len(p.ranges) == 0:
		return "reject 1-65535"
	case len(p.ranges) == 1 && p.ranges[0] == (PortRange{Lo: 0, Hi: 65535}):
		return "accept 1-65535"
	}
	return "accept " + p.String()
}

const (
	LEVEL_ASN  = 1
	LEVEL_P24  = 2
	LEVEL_P16  = 3
	LEVEL_IPV6 = 4
)

func IPLevel(ipStr string, asn uint32) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP")
	}

	if ip4 := ip.To4(); ip4 != nil {

		if asn != 0 {
			return uint32(LEVEL_ASN<<28) | (asn & 0x0FFFFFFF), nil
		}

		p24 := uint32(ip4[0])<<8 |
			uint32(ip4[1])

		return uint32(LEVEL_P24<<28) | p24, nil
	}

	ip = ip.To16()
	if ip == nil {
		return 0, fmt.Errorf("invalid IP")
	}

	var v uint32
	for i := range 4 {
		v = (v << 8) | uint32(ip[i])
	}

	return uint32(LEVEL_IPV6<<28) | v, nil
}

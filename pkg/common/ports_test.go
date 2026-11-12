package common

import (
	"strconv"
	"strings"
	"testing"
)

// referencePolicy evaluates a "p" exit policy summary port by port, the way
// the former bit-per-port representation did (dir-spec "p" item: an accept
// or reject keyword and a PortList; port 0 is never accepted).
func referencePolicy(t *testing.T, line string) [65536]bool {
	t.Helper()
	keyword, list, _ := strings.Cut(line, " ")
	var allowed [65536]bool
	if keyword == "reject" {
		for i := range allowed {
			allowed[i] = true
		}
	}
	for _, item := range strings.Split(list, ",") {
		a, b, isRange := strings.Cut(item, "-")
		lo, err := strconv.Atoi(a)
		if err != nil {
			t.Fatal(err)
		}
		hi := lo
		if isRange {
			if hi, err = strconv.Atoi(b); err != nil {
				t.Fatal(err)
			}
		}
		for n := lo; n <= hi; n++ {
			allowed[n] = keyword == "accept"
		}
	}
	allowed[0] = false
	return allowed
}

// TestPortsMatchReference compares the range representation with a port by
// port evaluation on policy summaries taken from the live microdesc
// consensus of 2026-11-11 (the reduced exit policy, a reject-style summary,
// accept/reject all) plus edge cases.
func TestPortsMatchReference(t *testing.T) {
	lines := []string{
		"accept 20-23,43,53,79-81,88,110,143,194,220,389,443,464-465," +
			"531,543-544,554,563,587,636,706,749,873,902-904,981," +
			"989-995,1194,1220,1293,1500,1533,1677,1723,1755,1863," +
			"2082-2083,2086-2087,2095-2096,2102-2104,3128,3389,3690," +
			"4321,4643,5050,5190,5222-5223,5228,5900,6660-6669,6679," +
			"6697,8000,8008,8074,8080,8082,8087-8088,8232-8233," +
			"8332-8333,8443,8888,9418,9999-10000,11371,19294,19638," +
			"50002,64738",
		"reject 25,119,135-139,445,563,1214,4661-4666,6346-6429,6699," +
			"6881-6999",
		"accept 1-65535",
		"reject 1-65535",
		"accept 443",
		"accept 65535",
		"reject 1",
		"accept 80,81,82,79",
		"accept 1-10,5-20,30-40,21-29",
	}
	for _, line := range lines {
		var p Ports
		if err := ParseDirectoryPorts(&p, line); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		want := referencePolicy(t, line)
		for n := range 65536 {
			if p.IsAllowed(uint16(n)) != want[n] {
				t.Fatalf("%q: port %d allowed=%v, want %v", line,
					n, p.IsAllowed(uint16(n)), want[n])
			}
		}

		// The cache representation round-trips exactly.
		back, err := ParsePortRanges(p.String())
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if p.String() != back.String() {
			t.Fatalf("%q: round trip %q != %q", line, back.String(),
				p.String())
		}

		// So does the policy line rendering.
		var again Ports
		err = ParseDirectoryPorts(&again, FormatPortsPolicy(&p))
		if err != nil || again.String() != p.String() {
			t.Fatalf("%q: policy round trip %q, %v", line,
				again.String(), err)
		}
	}
}

// TestPortsCompact checks the ranges are merged and that the common cases
// need no or few ranges.
func TestPortsCompact(t *testing.T) {
	var p Ports
	if err := ParseDirectoryPorts(&p, "reject 1-65535"); err != nil {
		t.Fatal(err)
	}
	if p.ranges != nil {
		t.Fatalf("reject all kept ranges %v", p.ranges)
	}
	if err := ParseDirectoryPorts(&p, "accept 80,81,82,79,1-10,5-20"); err != nil {
		t.Fatal(err)
	}
	if got := p.String(); got != "1-20,79-82" {
		t.Fatalf("got %q", got)
	}

	// Removing from the middle splits a range; adding back merges it.
	p.SetPort(15, false)
	if got := p.String(); got != "1-14,16-20,79-82" {
		t.Fatalf("got %q", got)
	}
	p.SetPort(15, true)
	if got := p.String(); got != "1-20,79-82" {
		t.Fatalf("got %q", got)
	}
}

// TestPortsCopyOnWrite checks that changing a copy never changes the
// original, as consensus clones share the ranges.
func TestPortsCopyOnWrite(t *testing.T) {
	var a Ports
	if err := ParseDirectoryPorts(&a, "accept 80-90"); err != nil {
		t.Fatal(err)
	}
	b := a
	b.SetPort(85, false)
	b.SetPort(443, true)
	if got := a.String(); got != "80-90" {
		t.Fatalf("original changed to %q", got)
	}
}

// TestPortsFromBitmap converts the representation of older caches.
func TestPortsFromBitmap(t *testing.T) {
	bitmap := make([]byte, 65536/8)
	for _, n := range []int{22, 80, 81, 82, 443, 65535} {
		bitmap[n/8] |= 1 << (n % 8)
	}
	p, err := PortsFromBitmap(bitmap)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.String(); got != "22,80-82,443,65535" {
		t.Fatalf("got %q", got)
	}
	if _, err := PortsFromBitmap(bitmap[1:]); err == nil {
		t.Fatal("short bitmap accepted")
	}
}

// TestParsePortRangesInvalid rejects malformed cache values.
func TestParsePortRangesInvalid(t *testing.T) {
	for _, s := range []string{"x", "10-5", "70000", "1,", "-1", "1-"} {
		if _, err := ParsePortRanges(s); err == nil {
			t.Fatalf("%q accepted", s)
		}
	}
}

// TestParsePortsLineMalformed rejects lines without exactly a keyword and a
// port list instead of indexing past them (found by FuzzPortsLine).
func TestParsePortsLineMalformed(t *testing.T) {
	for _, line := range []string{"", "accept", "reject", "allow 80", "accept 80 443", "accept  80"} {
		var p Ports
		if err := ParsePortsLine(&p, line); err == nil {
			t.Fatalf("%q accepted", line)
		}
	}
	var p Ports
	if err := ParsePortsLine(&p, "accept 80"); err != nil || !p.IsAllowed(80) {
		t.Fatalf("valid line rejected: %v", err)
	}
}

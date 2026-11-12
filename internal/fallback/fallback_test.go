package fallback

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/robogg133/gonion/internal/shared"
)

func TestFallbackRejectsInvalidPinsAndCancellation(t *testing.T) {
	for _, fingerprint := range []string{"", "not-hex", "01", "0000000000000000000000000000000000000000"} {
		fb := New([]shared.FallbackDir{{IPv4: "127.0.0.1", ORPort: 1, Fingerprint: fingerprint}})
		if _, err := fb.DialContext(context.Background(), false); err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(shared.Fallbacks).DialContext(ctx, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled fallback dial: %v", err)
	}
	if _, err := New(nil).Dial(false); err == nil {
		t.Fatal("empty fallback list accepted")
	}
}

func TestPinnedConnection(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	identity := [20]byte{1}
	c := &pinnedConn{Conn: a, identity: identity}
	if c.ExpectedRelayIdentity() != identity {
		t.Fatal("lost selected fallback identity")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte{1}); err == nil {
		t.Fatal("wrapper did not close the underlying connection")
	}
}

// listenFallback starts a TCP listener that accepts and holds connections,
// and returns a fallback entry pointing at it.
func listenFallback(t *testing.T, id byte) shared.FallbackDir {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	return shared.FallbackDir{
		IPv4:        "127.0.0.1",
		ORPort:      uint16(l.Addr().(*net.TCPAddr).Port),
		Fingerprint: strings.Repeat(fmt.Sprintf("%02X", id), 20),
	}
}

// closedFallback returns a fallback entry whose port refuses connections.
func closedFallback(t *testing.T, id byte) shared.FallbackDir {
	t.Helper()
	// A port that was free a moment ago refuses connections.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	return shared.FallbackDir{
		IPv4:        "127.0.0.1",
		ORPort:      uint16(port),
		Fingerprint: strings.Repeat(fmt.Sprintf("%02X", id), 20),
	}
}

// TestFallbackRandomChoice checks that every client doesn't pick the same
// first fallback: over many dials more than one reachable fallback is used,
// and each connection is pinned to the fallback it reached.
func TestFallbackRandomChoice(t *testing.T) {
	list := []shared.FallbackDir{
		listenFallback(t, 1), listenFallback(t, 2), listenFallback(t, 3),
	}
	byPort := make(map[int][20]byte)
	for _, fb := range list {
		raw, _ := hex.DecodeString(fb.Fingerprint)
		byPort[int(fb.ORPort)] = [20]byte(raw)
	}

	chosen := make(map[[20]byte]int)
	for range 60 {
		c, err := New(list).DialContext(context.Background(), false)
		if err != nil {
			t.Fatal(err)
		}
		pinned := c.(*pinnedConn)
		port := c.RemoteAddr().(*net.TCPAddr).Port
		if byPort[port] != pinned.ExpectedRelayIdentity() {
			t.Fatal("connection pinned to another fallback's identity")
		}
		chosen[pinned.ExpectedRelayIdentity()]++
		_ = c.Close()
	}
	if len(chosen) < 2 {
		t.Fatalf("always the same fallback: %v", chosen)
	}
}

// TestFallbackSkipsUnreachable checks that an unreachable fallback is skipped.
func TestFallbackSkipsUnreachable(t *testing.T) {
	up := listenFallback(t, 7)
	list := []shared.FallbackDir{closedFallback(t, 8), up, closedFallback(t, 9)}
	for range 10 {
		c, err := New(list).DialContext(context.Background(), false)
		if err != nil {
			t.Fatal(err)
		}
		if got := c.RemoteAddr().(*net.TCPAddr).Port; got != int(up.ORPort) {
			t.Fatalf("connected to port %d", got)
		}
		_ = c.Close()
	}
}

// TestRandomOrderIsPermutation checks the shuffle keeps every index once.
func TestRandomOrderIsPermutation(t *testing.T) {
	for _, n := range []int{0, 1, 2, 200} {
		order, err := randomOrder(n)
		if err != nil {
			t.Fatal(err)
		}
		seen := make(map[int]bool)
		for _, i := range order {
			if i < 0 || i >= n || seen[i] {
				t.Fatalf("n=%d: bad order %v", n, order)
			}
			seen[i] = true
		}
		if len(order) != n {
			t.Fatalf("n=%d: %d entries", n, len(order))
		}
	}
}

// TestIPv6Endpoint covers both forms of the IPv6 field: the bracketed
// consensus "a" form with its own port (as the list currently holds it) and
// a bare address with IPv6Port.
func TestIPv6Endpoint(t *testing.T) {
	cases := []struct {
		ipv6 string
		port uint16
		want string
	}{
		{"[2a10:3781:16ea:90:45:80:171:211]:443", 9001,
			"[2a10:3781:16ea:90:45:80:171:211]:443"},
		{"2001:db8::1", 9001, "[2001:db8::1]:9001"},
		{"[2001:db8::1]", 9001, "[2001:db8::1]:9001"},
		{"2001:db8::1", 0, ""},
		{"[2001:db8::1]:0", 9001, ""},
		{"::ffff:192.0.2.1", 9001, ""},
		{"192.0.2.1", 9001, ""},
		{"not an address", 9001, ""},
		{"", 9001, ""},
	}
	for _, tc := range cases {
		got, ok := ipv6Endpoint(shared.FallbackDir{
			IPv6: tc.ipv6, IPv6Port: tc.port,
		})
		if tc.want == "" {
			if ok {
				t.Fatalf("%q: accepted %v", tc.ipv6, got)
			}
			continue
		}
		if !ok || got.String() != tc.want {
			t.Fatalf("%q: got %v %v, want %s", tc.ipv6, got, ok, tc.want)
		}
	}
}

// TestFallbackUsesIPv6 connects over IPv6 when the IPv4 port is closed.
func TestFallbackUsesIPv6(t *testing.T) {
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			defer c.Close()
			_, _ = c.Read(make([]byte, 1))
		}
	}()
	fb := closedFallback(t, 5)
	fb.IPv6 = l.Addr().String()
	c, err := New([]shared.FallbackDir{fb}).DialContext(
		context.Background(), true,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if ip := c.RemoteAddr().(*net.TCPAddr).IP; ip.To4() != nil {
		t.Fatalf("connected over %v", ip)
	}
}

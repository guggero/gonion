package fallback

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/robogg133/gonion/internal/shared"
)

type FallBackDialer struct {
	list []shared.FallbackDir
}

func New(list []shared.FallbackDir) *FallBackDialer {
	return &FallBackDialer{
		list: append([]shared.FallbackDir(nil), list...),
	}
}

// Dial creates a new fallbackdialer with default fallback dirs list and dial
func Dial(ipv6Enabled bool) (net.Conn, error) {
	return New(shared.Fallbacks).Dial(ipv6Enabled)
}

func (fb *FallBackDialer) Dial(tryipv6 bool) (net.Conn, error) {
	return fb.DialContext(context.Background(), tryipv6)
}

// DialContext connects to a fallback chosen at random (dir-spec,
// client-operation: a client without a consensus downloads it "from a
// randomly chosen fallback directory mirror"), trying the others in random
// order if it can't be reached. Walking the list in order would send every
// client to the same first fallback. The connection carries the selected
// fallback's RSA identity into the OR handshake; returning only its address
// would lose the identity pin.
func (fb *FallBackDialer) DialContext(ctx context.Context, tryipv6 bool) (net.Conn, error) {
	order, err := randomOrder(len(fb.list))
	if err != nil {
		return nil, err
	}
	var failures []error
	for _, i := range order {
		v := fb.list[i]
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw, err := hex.DecodeString(v.Fingerprint)
		if err != nil || len(raw) != 20 || [20]byte(raw) == [20]byte{} || net.ParseIP(v.IPv4).To4() == nil || v.ORPort == 0 {
			failures = append(failures, fmt.Errorf("fallback: invalid identity or IPv4 endpoint"))
			continue
		}
		addresses := []string{net.JoinHostPort(v.IPv4, strconv.Itoa(int(v.ORPort)))}
		if tryipv6 {
			if addr, ok := ipv6Endpoint(v); ok {
				addresses = append(addresses, addr.String())
			}
		}
		for _, addr := range addresses {
			conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", addr)
			if err == nil {
				return &pinnedConn{Conn: conn, identity: [20]byte(raw), redial: func(ctx context.Context) (net.Conn, error) {
					return New([]shared.FallbackDir{v}).DialContext(ctx, tryipv6)
				}}, nil
			}
			failures = append(failures, err)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
	}
	if len(failures) == 0 {
		return nil, fmt.Errorf("fallback: no directory relays configured")
	}
	return nil, errors.Join(failures...)
}

// randomOrder returns a uniformly random permutation of 0..n-1 (crypto/rand
// Fisher-Yates), so the fallback choice can't be predicted.
func randomOrder(n int) ([]int, error) {
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, fmt.Errorf("fallback: random order: %w", err)
		}
		order[i], order[j.Int64()] = order[j.Int64()], order[i]
	}
	return order, nil
}

// ipv6Endpoint returns a fallback's IPv6 OR address. The IPv6 field is either
// a bare address with the port in IPv6Port, or a consensus "a" style
// "[address]:port" whose own port takes precedence.
func ipv6Endpoint(v shared.FallbackDir) (netip.AddrPort, bool) {
	if v.IPv6 == "" {
		return netip.AddrPort{}, false
	}
	if ap, err := netip.ParseAddrPort(v.IPv6); err == nil {
		if !ap.Addr().Is6() || ap.Addr().Is4In6() || ap.Port() == 0 {
			return netip.AddrPort{}, false
		}
		return ap, true
	}
	addr, err := netip.ParseAddr(strings.Trim(v.IPv6, "[]"))
	if err != nil || !addr.Is6() || addr.Is4In6() || v.IPv6Port == 0 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, v.IPv6Port), true
}

type pinnedConn struct {
	net.Conn
	identity [20]byte
	redial   func(context.Context) (net.Conn, error)
}

func (c *pinnedConn) ExpectedRelayIdentity() [20]byte { return c.identity }

// RedialExpectedRelay reconnects only the originally selected fallback. It
// never substitutes a different fallback when that address is unavailable.
func (c *pinnedConn) RedialExpectedRelay(ctx context.Context, expected [20]byte) (net.Conn, error) {
	if expected == [20]byte{} || expected != c.identity || c.redial == nil {
		return nil, fmt.Errorf("fallback: selected identity has no matching redial policy")
	}
	return c.redial(ctx)
}

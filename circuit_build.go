package gonion

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"net"

	"github.com/robogg133/gonion/pkg/common"
	"github.com/robogg133/gonion/pkg/handshakes"

	"github.com/robogg133/gonion/pkg/hs/onion"
	"github.com/robogg133/gonion/pkg/lspec"
)

// NewCircuitTo creates a 1-hop ntor circuit to guard.
func (c *Conn) NewCircuitTo(id uint32, guard *common.RouterStatus) (*Circuit, error) {
	if err := c.CheckRelayIdentity(guard); err != nil {
		return nil, err
	}
	hs, err := newNTorHandshake(guard)
	if err != nil {
		return nil, fail(c.ctx, ErrCircuit, "build ntor handshake failed", err)
	}
	return c.NewCircuit(id, handshakes.HTYPE_NTOR, hs)
}

// ExtendTo extends the circuit one hop toward relay via EXTEND2 + ntor.
func (c *Circuit) ExtendTo(relay *common.RouterStatus) error {
	lspecs, err := linkSpecsFor(relay)
	if err != nil {
		return fail(c.Ctx, ErrExtend, "build link specs failed", err)
	}
	hs, err := newNTorHandshake(relay)
	if err != nil {
		return fail(c.Ctx, ErrExtend, "build ntor handshake failed", err)
	}
	return c.Extend(lspecs, handshakes.HTYPE_NTOR, hs)
}

// BuildPath creates the onion path for relays[0]=guard … relays[n-1]=exit.
// The circuit must be empty; hop 0 is created, the rest are extended. The id
// argument is retained for source compatibility (see NewCircuit).
func (c *Conn) BuildPath(id uint32, relays []*common.RouterStatus) (*Circuit, error) {
	_ = id
	return c.BuildPathContext(context.Background(), relays)
}

// BuildPathContext is BuildPath bound to ctx. Cancellation tears down only
// the circuit being built, never the connection, which other circuits may
// share. Every step is also bounded by CIRCUIT_BUILD_TIMEOUT.
func (c *Conn) BuildPathContext(ctx context.Context, relays []*common.RouterStatus) (*Circuit, error) {
	if len(relays) == 0 {
		return nil, Public(ErrCircuit, "empty path")
	}
	if err := c.CheckRelayIdentity(relays[0]); err != nil {
		return nil, err
	}
	hs, err := newNTorHandshake(relays[0])
	if err != nil {
		return nil, fail(c.ctx, ErrCircuit, "build ntor handshake failed", err)
	}
	stepCtx, cancel := context.WithTimeout(ctx, CIRCUIT_BUILD_TIMEOUT)
	circ, err := c.NewCircuitContext(stepCtx, handshakes.HTYPE_NTOR, hs)
	cancel()
	if err != nil {
		return nil, err
	}
	for i, r := range relays[1:] {
		if err := circ.extendToContext(ctx, r); err != nil {
			// Path-bias accounting (pkg/path) must tell a guard-handshake
			// failure from a failure after the guarded build committed a second
			// hop (path-spec §7.1). Wrap the error with the hops that were open.
			hops := circ.HopCount()
			_ = circ.Close()
			return nil, &pathBiasHopsError{err: failf(circ.Ctx, ErrExtend, err, "extend hop %d failed", i+1), hops: hops}
		}
	}
	return circ, nil
}

// extendToContext is ExtendTo bound to ctx and CIRCUIT_BUILD_TIMEOUT.
func (c *Circuit) extendToContext(ctx context.Context, relay *common.RouterStatus) error {
	lspecs, err := linkSpecsFor(relay)
	if err != nil {
		return fail(c.Ctx, ErrExtend, "build link specs failed", err)
	}
	hs, err := newNTorHandshake(relay)
	if err != nil {
		return fail(c.Ctx, ErrExtend, "build ntor handshake failed", err)
	}
	stepCtx, cancel := context.WithTimeout(ctx, CIRCUIT_BUILD_TIMEOUT)
	defer cancel()
	return c.ExtendContext(stepCtx, lspecs, handshakes.HTYPE_NTOR, hs)
}

// pathBiasHopsError marks a multi-hop build that failed inside its extension
// loop, after the guard handshake completed, and reports how many hops were
// open at the failure. It is plumbing only: the guard reachability attribution
// and every protocol behavior stay with the underlying error.
type pathBiasHopsError struct {
	err  error
	hops int
}

// PathBiasHops is the read-only hop progress signal for path-bias accounting.
func (e *pathBiasHopsError) PathBiasHops() int { return e.hops }

func (e *pathBiasHopsError) Error() string { return e.err.Error() }
func (e *pathBiasHopsError) Unwrap() error { return e.err }

// Dial opens a stream to addr (host:port) through the circuit exit hop. The
// source-compatible wrapper supplies a bounded begin deadline.
func (c *Circuit) Dial(addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(c.Ctx, STREAM_BEGIN_TIMEOUT)
	defer cancel()
	return c.DialContext(ctx, addr)
}

// DialContext opens a stream while honoring the caller's context/deadline.
// Cancellation after a successful Dial does not close the returned connection.
func (c *Circuit) DialContext(ctx context.Context, addr string) (net.Conn, error) {
	if c.hops.Len() == 0 {
		return nil, Public(ErrCircuit, "empty circuit")
	}
	isOnion, err := onion.IsOnion(addr)
	if err != nil {
		return nil, err
	}
	if isOnion {
		return c.dialOnion(addr)
	}
	stream, err := c.NewStreamContext(ctx, addr, c.hops.Len()-1)
	if err != nil {
		return nil, err
	}
	return stream.Conn(), nil
}

func (c *Circuit) dialOnion(addr string) (net.Conn, error) {
	if _, err := onion.NewFromString(addr); err != nil {
		return nil, err
	}
	// One existing circuit cannot provide the separate directory, introduction
	// and rendezvous circuits or dial their selected guards.
	return nil, Public(ErrCircuit, "onion dialing requires embed.Client.DialContext")
}

func newNTorHandshake(r *common.RouterStatus) (*handshakes.Client_NTorHandshake, error) {
	if r == nil {
		return nil, Public(ErrCircuit, "nil relay")
	}
	if r.NTorOnionKey == nil {
		return nil, Publicf(ErrCircuit, "relay %s missing ntor key", r.Nickname)
	}
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &handshakes.Client_NTorHandshake{
		NodeID:     r.NodeID,
		KeyID:      r.NTorOnionKey,
		PrivateKey: sk,
		PublicKey:  sk.PublicKey(),
	}, nil
}

func linkSpecsFor(r *common.RouterStatus) ([]lspec.Lspec, error) {
	if r == nil {
		return nil, Public(ErrExtend, "nil extension target")
	}
	if len(r.LinkSpecifiers) != 0 {
		reader := bytes.NewReader(r.LinkSpecifiers[1:])
		var specs []lspec.Lspec
		for i := 0; i < int(r.LinkSpecifiers[0]); i++ {
			spec, err := lspec.Read(reader)
			if err != nil {
				return nil, err
			}
			specs = append(specs, spec)
		}
		if reader.Len() != 0 || len(specs) == 0 {
			return nil, Public(ErrExtend, "invalid link specifier block")
		}
		return specs, nil
	}
	if r.Ipv4Addr == "" || r.ORPort == 0 {
		return nil, Publicf(ErrExtend, "relay %s missing OR address", r.Nickname)
	}
	ip, err := lspec.NewLespecFromIPText(fmt.Sprintf("%s:%d", r.Ipv4Addr, r.ORPort))
	if err != nil {
		return nil, err
	}
	if len(r.IdEd25519) != 32 {
		return nil, Publicf(ErrExtend, "relay %s missing ed25519 id", r.Nickname)
	}
	return []lspec.Lspec{
		ip,
		lspec.NewNodeID(r.NodeID),
		lspec.NewEd25519ID(r.IdEd25519),
	}, nil
}

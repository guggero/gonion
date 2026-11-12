package json

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

func TestRoundTrip(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := priv.PublicKey()

	interval := uint64(1440)
	c := &common.Consensus{
		NetowrkStatusVersion: 3,
		Flavor:               common.ConsensusFlavorMicrodesc,
		SharedPreviousValue:  [32]byte{4, 5, 6},
		HsdirInterval:        &interval,
		ValidAfter:           time.Date(2026, 1, 30, 22, 0, 0, 0, time.UTC),
		FreshUntil:           time.Date(2026, 1, 30, 23, 0, 0, 0, time.UTC),
		ValidUntil:           time.Date(2026, 1, 31, 1, 0, 0, 0, time.UTC),
		SharedCurrentValue:   [32]byte{1, 2, 3},
		BandWidthWeight:      common.BandWidthWeight{Wbe: 1, Wgm: 2},
		RelayInformation: []common.RouterStatus{
			{
				Nickname:              "relay1",
				NodeID:                [20]byte{9, 9, 9},
				Ipv4Addr:              "1.2.3.4",
				IPLevel:               0x20000102,
				ORPort:                9001,
				DirPort:               9030,
				BandWidth:             102400,
				Ipv6Addr:              "[2001:db8::1]:9001",
				MicrodescriptorDigest: "fXPextdkQnmBDwYmo0UHLbUhaU6C0slh/NQVtZn1VU0",
				MicrodescriptorLoaded: true,
				ProtoVersions:         common.Proto{Link: 0b11000, Relay: 0b10100},
				StatusFlags:           [common.FLAG_ARRAY_LENGTH + 1]bool{0: true, 5: true},
				OnionKey:              []byte("fake rsa bytes"),
				NTorOnionKey:          key,
				IdEd25519:             bytes.Repeat([]byte{0xde}, 32),
				Family:                []common.Family{{Digest: []byte{1, 2}}, {Nickname: "nick"}},
				Familys:               []*common.FamilyIDs{{Kind: "AAP", Value: []byte{0xbe, 0xef}}},
			},
		},
	}
	c.RelayInformation[0].Ports.SetPort(22, true)
	c.RelayInformation[0].Ports.SetPort(443, true)

	b, err := (Parser{}).Format(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := (Parser{}).Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("reparse: %v\n%s", err, b)
	}
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("round-trip mismatch:\ngot  %+v\nwant %+v", got, c)
	}
}

// TestLegacyPortsBitmap loads a cache written before exit ports were kept as
// ranges, when they were a base64 bit-per-port bitmap.
func TestLegacyPortsBitmap(t *testing.T) {
	c := &common.Consensus{
		NetowrkStatusVersion: 3,
		Flavor:               common.ConsensusFlavorMicrodesc,
		ValidAfter:           time.Date(2026, 1, 30, 22, 0, 0, 0, time.UTC),
		FreshUntil:           time.Date(2026, 1, 30, 23, 0, 0, 0, time.UTC),
		ValidUntil:           time.Date(2026, 1, 31, 1, 0, 0, 0, time.UTC),
		RelayInformation: []common.RouterStatus{{
			Nickname:              "old",
			NodeID:                [20]byte{9, 9, 9},
			Ipv4Addr:              "192.0.2.1",
			ORPort:                9001,
			MicrodescriptorDigest: "fXPextdkQnmBDwYmo0UHLbUhaU6C0slh/NQVtZn1VU0",
		}},
	}
	c.RelayInformation[0].Ports.SetPort(1, true)
	current, err := (Parser{}).Format(c)
	if err != nil {
		t.Fatal(err)
	}

	// Replace the ranges by the bitmap of an older cache.
	bitmap := make([]byte, 65536/8)
	for _, n := range []int{22, 443, 444} {
		bitmap[n/8] |= 1 << (n % 8)
	}
	legacy := bytes.Replace(
		current, []byte(`"PortRanges":"1"`), []byte(`"Ports":"`+
			base64.StdEncoding.EncodeToString(bitmap)+`"`), 1,
	)
	if bytes.Equal(legacy, current) {
		t.Fatalf("no port ranges in %s", current)
	}

	got, err := (Parser{}).Parse(bytes.NewReader(legacy))
	if err != nil {
		t.Fatal(err)
	}
	ports := got.RelayInformation[0].Ports
	if s := ports.String(); s != "22,443-444" {
		t.Fatalf("got %q", s)
	}

	// It is written back as ranges.
	b, err := (Parser{}).Format(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"PortRanges":"22,443-444"`)) ||
		bytes.Contains(b, []byte(`"Ports":`)) {

		t.Fatalf("unexpected cache: %s", b)
	}
}

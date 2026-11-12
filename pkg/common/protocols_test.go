package common

import "testing"

// TestParseProtocolSet parses the consensus lists as published (tor-spec,
// "Required and recommended subprotocols") into a canonical form.
func TestParseProtocolSet(t *testing.T) {
	cases := map[string]string{
		"Cons=2 Desc=2-4 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2-3 Relay=2-6": "Cons=2 Desc=2-4 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2-3 Relay=2-6",
		"Relay=2 Link=1-3,5":     "Link=1-3,5 Relay=2",
		"Link=5,1,2-3 Relay=4,2": "Link=1-3,5 Relay=2,4",
		"Link=0-63":              "Link=0-63",
		"Padding=":               "Padding=",
		"":                       "",
	}
	for in, want := range cases {
		p, err := ParseProtocolSet(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got := p.String(); got != want {
			t.Fatalf("%q: got %q, want %q", in, got, want)
		}
	}

	for _, bad := range []string{
		"Link", "=4", "Link=64", "Link=4-2", "Link=x", "Link=1,,2",
		"Link=4 Link=5", "Li-nk=4", "Link=-1",
	} {
		if _, err := ParseProtocolSet(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// TestProtocolSetMissing treats every capability as its own flag: supporting
// Relay=2 doesn't imply Relay=1.
func TestProtocolSetMissing(t *testing.T) {
	required := mustParseProtocolSet("Cons=2 Desc=2 FlowCtrl=1 Link=4 Microdesc=2 Relay=1-2")
	have := mustParseProtocolSet("Cons=1-2 Desc=1-3 FlowCtrl=1 Link=4-5 Microdesc=1-3 Relay=2")
	if got := required.Missing(have).String(); got != "Relay=1" {
		t.Fatalf("missing %q", got)
	}
	if got := mustParseProtocolSet("Conflux=1 Link=4").Missing(have).String(); got != "Conflux=1" {
		t.Fatalf("missing %q", got)
	}

	// Today's required client list is fully supported.
	today := mustParseProtocolSet("Cons=2 Desc=2 FlowCtrl=1 Link=4 Microdesc=2 Relay=2")
	if missing := today.Missing(ClientProtocols); len(missing) != 0 {
		t.Fatalf("missing %v", missing)
	}
}

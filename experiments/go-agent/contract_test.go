package main

// The server contract distinguishes three states per key (CLAUDE.md, docker,
// wireguard, openvpn, proxmox...):
//   key absent  -> an older agent, the server changes nothing
//   null        -> collection FAILED, the server must not prune
//   []          -> a confirmed empty read, the server prunes everything
// encoding/json maps these onto Go values in ways that invert them silently.

import (
	"encoding/json"
	"testing"
)

func marshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNilSliceIsNullNotEmpty(t *testing.T) {
	var peers []string // "zero peers" written the idiomatic Go way
	if got := marshal(t, map[string]any{"peers": peers}); got != `{"peers":null}` {
		t.Fatalf("got %s", got)
	}
	// A genuinely empty read now reads as a FAILURE: the server never prunes.
	if got := marshal(t, map[string]any{"peers": []string{}}); got != `{"peers":[]}` {
		t.Fatalf("got %s", got)
	}
}

func TestOmitemptyDropsTheConfirmedEmptyRead(t *testing.T) {
	type WireGuard struct {
		Peers []string `json:"peers,omitempty"`
	}
	// omitempty cannot tell nil from empty: the prune-all [] becomes an ABSENT
	// key, which the server reads as "older agent" and ignores.
	if got := marshal(t, WireGuard{Peers: []string{}}); got != `{}` {
		t.Fatalf("got %s", got)
	}
}

func TestThreeStatesNeedAnExplicitType(t *testing.T) {
	// What a port needs instead: an explicit tri-state, marshalled by hand.
	type Field struct {
		Present bool
		Value   []string // nil = null (failure) when Present
	}
	render := func(name string, f Field) map[string]any {
		out := map[string]any{}
		if f.Present {
			if f.Value == nil {
				out[name] = nil
			} else {
				out[name] = f.Value
			}
		}
		return out
	}
	cases := map[string]Field{
		`{}`:             {},
		`{"peers":null}`: {Present: true},
		`{"peers":[]}`:   {Present: true, Value: []string{}},
	}
	for want, f := range cases {
		if got := marshal(t, render("peers", f)); got != want {
			t.Fatalf("want %s, got %s", want, got)
		}
	}
}

func TestCallBoundedAbandonsAndSingleFlights(t *testing.T) {
	release := make(chan struct{})
	stuck := func() (any, error) { <-release; return 1, nil }
	if _, err := callBounded("stuck", 10e6, stuck); err == nil {
		t.Fatal("expected a timeout")
	}
	// While the first call is still blocked, no second worker is started.
	if _, err := callBounded("stuck", 10e6, func() (any, error) { t.Fatal("ran"); return nil, nil }); err == nil {
		t.Fatal("expected single-flight refusal")
	}
	close(release)
}

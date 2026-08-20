package config

import (
	"strings"
	"testing"
)

// TestUnknownKeysDoNotBreakParsing reproduces the field incident: a config
// written by a NEWER SocksIt (here: a key this build has never heard of) must
// still load. Rejecting it took the datapath down — the service refused its own
// config and the panel reported "config is not valid yet".
func TestUnknownKeysDoNotBreakParsing(t *testing.T) {
	y := "proxy:\n  address: 10.0.0.1\n  port: 1080\nmode: allowlist\napps: [chrome.exe]\nfuture_knob_from_a_newer_build: [1, 2]\n"

	c, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("a config with an unknown key must still parse, got %v", err)
	}
	if c.Proxy.Address != "10.0.0.1" || len(c.Apps) != 1 {
		t.Errorf("known fields lost: %+v", c.Proxy)
	}

	// It is still reported, so a typo is discoverable where the user asks.
	unknown := UnknownKeys([]byte(y))
	if len(unknown) != 1 || unknown[0] != "future_knob_from_a_newer_build" {
		t.Errorf("UnknownKeys = %v, want [future_knob_from_a_newer_build]", unknown)
	}
	if got := UnknownKeys([]byte("proxy:\n  address: 10.0.0.1\nmode: allowlist\n")); len(got) != 0 {
		t.Errorf("a clean config must report no unknown keys, got %v", got)
	}

	// A genuine syntax error is still an error from Parse.
	if _, err := Parse([]byte("proxy: [unclosed\n")); err == nil {
		t.Error("malformed YAML must still fail")
	}

	// Real validation still applies (unknown keys are not a free pass).
	if _, err := Parse([]byte("mode: allowlist\nfuture_knob: 1\n")); err == nil {
		t.Error("a config missing proxy.address must still be rejected")
	} else if !strings.Contains(err.Error(), "proxy.address") {
		t.Errorf("unexpected error: %v", err)
	}
}

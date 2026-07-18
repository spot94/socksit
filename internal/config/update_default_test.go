package config

import "testing"

// TestUpdateEndpointBackfilled guards the regression where a config without an
// update block shipped with updates silently disabled (empty endpoint), so a new
// user could not update until they typed the URL by hand.
func TestUpdateEndpointBackfilled(t *testing.T) {
	if Default().Update.Endpoint == "" {
		t.Fatal("Default() must set update.endpoint")
	}

	// A minimal config that omits the update block must come back with the endpoint
	// filled and update checks enabled (default mode is notify).
	c := ParseLenient([]byte("proxy:\n  address: 10.0.0.1\n  port: 1080\napps: []\nmode: allowlist\n"))
	if c.Update.Endpoint == "" {
		t.Error("applyDefaults must backfill update.endpoint")
	}
	if !c.UpdatesEnabled() {
		t.Errorf("updates should be enabled by default, got endpoint=%q mode=%q", c.Update.Endpoint, c.Update.Mode)
	}

	// mode: off still disables checks even with the endpoint present.
	off := ParseLenient([]byte("proxy:\n  address: 10.0.0.1\n  port: 1080\nmode: allowlist\nupdate:\n  mode: off\n"))
	if off.UpdatesEnabled() {
		t.Error("mode: off must disable update checks")
	}
}

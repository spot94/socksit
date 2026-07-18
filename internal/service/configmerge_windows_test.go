//go:build windows

package service

import (
	"testing"

	"socksit/internal/config"
)

// TestMergeManagedOverride: remote specifies some fields + apps; override keeps
// local values for omitted fields, overrides specified ones, and unions apps.
func TestMergeManagedOverride(t *testing.T) {
	local := config.Default()
	local.Proxy.Address = "10.0.0.1"
	local.Proxy.Port = 1081
	local.Mode = config.ModeBlocklist
	local.Apps = []string{"user1.exe"}
	local.ConfigSource.URL = "https://cfg.local/socksit.yaml"
	local.ConfigSource.Merge = config.MergeOverride

	remote := []byte("proxy:\n  address: 10.0.0.9\napps:\n  - remote1.exe\n  - Remote2.exe\nmode: allowlist\n")
	got, err := mergeManagedConfig(local, remote)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if got.Proxy.Address != "10.0.0.9" {
		t.Errorf("proxy.address should be overridden by remote, got %q", got.Proxy.Address)
	}
	if got.Proxy.Port != 1081 {
		t.Errorf("proxy.port omitted by remote should stay local 1081, got %d", got.Proxy.Port)
	}
	if got.Mode != config.ModeAllowlist {
		t.Errorf("mode should be overridden to allowlist, got %q", got.Mode)
	}
	if len(got.Apps) != 1 || got.Apps[0] != "user1.exe" {
		t.Errorf("user's own apps must be preserved, got %v", got.Apps)
	}
	if len(got.ManagedApps) != 2 {
		t.Errorf("managed_apps should mirror remote apps, got %v", got.ManagedApps)
	}
	if eff := got.EffectiveApps(); len(eff) != 3 {
		t.Errorf("effective apps should union user+managed (3), got %v", eff)
	}
	if got.MergeMode() != config.MergeOverride {
		t.Errorf("local config_source (merge=override) must be preserved, got %q", got.ConfigSource.Merge)
	}
	if got.ConfigSource.URL != local.ConfigSource.URL {
		t.Errorf("config_source.url must be preserved, got %q", got.ConfigSource.URL)
	}
}

// TestMergeOmittedKeepsLocal: a field the remote omits keeps the local value even
// when that value differs from the built-in default.
func TestMergeOmittedKeepsLocal(t *testing.T) {
	local := config.Default()
	local.Proxy.Address = "10.0.0.1"
	off := false
	local.KillSwitch = &off // non-default; remote omits kill_switch
	local.ConfigSource.URL = "https://cfg.local/socksit.yaml"
	local.ConfigSource.Merge = config.MergeOverride

	got, err := mergeManagedConfig(local, []byte("proxy:\n  address: 10.0.0.9\n"))
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if got.KillSwitchOn() {
		t.Errorf("kill_switch omitted by remote must stay local false, got true")
	}
}

// TestDeepMergeNested: nested maps merge key-by-key rather than wholesale replace.
func TestDeepMergeNested(t *testing.T) {
	base := map[string]any{"proxy": map[string]any{"address": "a", "port": 1}, "mode": "allowlist"}
	patch := map[string]any{"proxy": map[string]any{"address": "b"}}
	out := deepMerge(base, patch)
	pm := out["proxy"].(map[string]any)
	if pm["address"] != "b" {
		t.Errorf("nested address should override, got %v", pm["address"])
	}
	if pm["port"] != 1 {
		t.Errorf("nested port should be kept, got %v", pm["port"])
	}
	if out["mode"] != "allowlist" {
		t.Errorf("top-level mode kept, got %v", out["mode"])
	}
}

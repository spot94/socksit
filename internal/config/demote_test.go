package config

import "testing"

func TestDemoteIfUnmanaged(t *testing.T) {
	// A managed config (url set) is never demoted.
	m := Default()
	m.ConfigSource.URL = "https://cfg/socksit.yaml"
	m.ManagedApps = []string{"feed.exe"}
	if m.DemoteIfUnmanaged() {
		t.Error("managed config must not be demoted")
	}
	if len(m.ManagedApps) != 1 {
		t.Error("managed config's managed_apps must be left intact")
	}

	// Unmanaged with channel remnants: drop managed lists + reset trust/lock.
	c := Default()
	c.Proxy.Address = "10.0.0.1"
	c.Apps = []string{"mine.exe"}
	c.ManagedApps = []string{"feed.exe"}
	c.ManagedSubnets = []string{"10.1.0.0/16"}
	c.ConfigSource.URL = ""
	c.ConfigSource.PubKey = "AAAA"
	c.ConfigSource.PendingPubKey = "BBBB"
	c.ConfigSource.Locked = []string{"kill_switch", "udp"}

	if !c.DemoteIfUnmanaged() {
		t.Fatal("expected demotion")
	}
	if len(c.ManagedApps) != 0 || len(c.ManagedSubnets) != 0 {
		t.Errorf("managed lists not dropped: %v %v", c.ManagedApps, c.ManagedSubnets)
	}
	if c.ConfigSource.PubKey != "" || c.ConfigSource.PendingPubKey != "" || len(c.ConfigSource.Locked) != 0 {
		t.Errorf("config_source trust/lock not reset: %+v", c.ConfigSource)
	}
	if c.IsLocked("kill_switch") || c.IsLocked("udp") {
		t.Error("toggles must be unlocked after demotion")
	}
	// Drop policy: the user's own apps survive, the channel's do not.
	if len(c.Apps) != 1 || c.Apps[0] != "mine.exe" {
		t.Errorf("user apps changed: %v", c.Apps)
	}
	if got := c.EffectiveApps(); len(got) != 1 || got[0] != "mine.exe" {
		t.Errorf("EffectiveApps after demotion = %v, want [mine.exe]", got)
	}
	// Idempotent.
	if c.DemoteIfUnmanaged() {
		t.Error("second demotion should be a no-op")
	}
}

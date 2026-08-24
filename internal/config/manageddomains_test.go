package config

import "testing"

// TestManagedDomainsUnionInOverrideMode: the feed's names add to the user's own,
// exactly like apps and subnets. Replacing instead of adding would silently drop
// the endpoint a user had to exempt locally to make an application work.
func TestManagedDomainsUnionInOverrideMode(t *testing.T) {
	c := Default()
	c.DirectDomains = []string{"agent-gw.example.com"}
	c.ManagedDomains = []string{".corp.example", "AGENT-GW.EXAMPLE.COM"}
	c.ConfigSource.URL = "https://cfg.example/socksit.yaml"
	c.ConfigSource.Merge = MergeOverride

	got := c.EffectiveDirectDomains()
	if len(got) != 2 || got[0] != "agent-gw.example.com" || got[1] != ".corp.example" {
		t.Errorf("expected the user's name first and the feed's added once, got %v", got)
	}

	// Replace mode has no separate managed set: the feed's list IS the config.
	c.ConfigSource.Merge = MergeReplace
	if got := c.EffectiveDirectDomains(); len(got) != 1 {
		t.Errorf("replace mode must not union, got %v", got)
	}
}

// TestManagedDomainsDroppedWhenUnmanaged: clearing the channel URL must drop what
// the channel contributed — keeping someone else's exemptions on a machine that
// no longer answers to that server is not a decision the user made.
func TestManagedDomainsDroppedWhenUnmanaged(t *testing.T) {
	c := Default()
	c.ManagedDomains = []string{".corp.example"}
	if !c.DemoteIfUnmanaged() {
		t.Fatal("dropping the feed's names must count as a change")
	}
	if c.ManagedDomains != nil {
		t.Errorf("the feed's names must be gone, got %v", c.ManagedDomains)
	}
}

// TestManagedDomainsAreValidated: a bad name in the feed would otherwise reach
// every client at once.
func TestManagedDomainsAreValidated(t *testing.T) {
	c := Default()
	c.Proxy.Address = "10.0.0.1"
	c.ManagedDomains = []string{"10.0.0.0/8"}
	if err := c.Validate(); err == nil {
		t.Error("a CIDR in managed_domains must be rejected")
	}
}

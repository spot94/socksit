package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestLegacyDirectDomainsMigrate: the key shipped briefly under `dns:` before it
// turned out to govern routing as much as DNS. A file written by that build must
// keep its setting rather than silently fall back to the defaults.
func TestLegacyDirectDomainsMigrate(t *testing.T) {
	y := "proxy:\n  address: 10.0.0.1\n  port: 1080\nmode: allowlist\ndns:\n  fakeip_v4: 198.18.0.0/15\n  direct_domains: [.corp.example]\n"
	c, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := c.EffectiveDirectDomains(); len(got) != 1 || got[0] != ".corp.example" {
		t.Errorf("legacy dns.direct_domains lost: %v", got)
	}
	// ...and it is not written back under dns, so the file converges on one key.
	out, err := yaml.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Count(string(out), "direct_domains") != 1 {
		t.Errorf("the key must be emitted once, at the top level:\n%s", out)
	}

	// The new key wins when both are present.
	y2 := "proxy:\n  address: 10.0.0.1\n  port: 1080\nmode: allowlist\ndirect_domains: [a.test]\ndns:\n  direct_domains: [b.test]\n"
	c2, err := Parse([]byte(y2))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := c2.EffectiveDirectDomains(); len(got) != 1 || got[0] != "a.test" {
		t.Errorf("top-level key must win, got %v", got)
	}
}

func TestDirectDomainsDefaultsAndValidation(t *testing.T) {
	y := "proxy:\n  address: 10.0.0.1\n  port: 1080\nmode: allowlist\n"
	c, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(c.EffectiveDirectDomains()) != len(DefaultDirectDomains) {
		t.Errorf("absent key must yield the defaults, got %v", c.EffectiveDirectDomains())
	}
	// An explicit empty list is the user's decision and must survive.
	c.DirectDomains = []string{}
	if got := c.EffectiveDirectDomains(); len(got) != 0 {
		t.Errorf("empty list must exempt nothing, got %v", got)
	}

	for _, bad := range []string{"10.0.0.0/8", "http://x.test", "*.x.test", "a b.test", "x..test"} {
		c.DirectDomains = []string{bad}
		if err := c.Validate(); err == nil {
			t.Errorf("%q must be rejected: it would silently match nothing", bad)
		}
	}
	for _, ok := range []string{"agent-gw.kimi.example", ".corp.local", "localhost"} {
		c.DirectDomains = []string{ok}
		if err := c.Validate(); err != nil {
			t.Errorf("%q must be accepted, got %v", ok, err)
		}
	}
}

// TestMachineWrittenDirectDomainsGetUpgraded: the first build of this feature
// persisted its 4-suffix default into socksit.yaml, so that exact set means
// "nobody chose this" — it must pick up the newer defaults (the Windows probes),
// while a hand-edited list is left alone.
func TestMachineWrittenDirectDomainsGetUpgraded(t *testing.T) {
	y := "proxy:\n  address: 10.0.0.1\n  port: 1080\nmode: allowlist\ndirect_domains: [.local, .lan, .internal, .home.arpa]\n"
	c, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := c.EffectiveDirectDomains()
	if len(got) != len(DefaultDirectDomains) {
		t.Errorf("the machine-written set must be upgraded to the defaults, got %v", got)
	}

	// One entry different = a human touched it.
	y2 := "proxy:\n  address: 10.0.0.1\n  port: 1080\nmode: allowlist\ndirect_domains: [.local, .lan, .internal]\n"
	c2, err := Parse([]byte(y2))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := c2.EffectiveDirectDomains(); len(got) != 3 {
		t.Errorf("a hand-edited list must be left alone, got %v", got)
	}
}

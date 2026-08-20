package config

import "testing"

// The 0.2.6/0.2.7 releases persisted BOTH their Class E fake-ip and their bypass
// list (which contained 198.18.0.0/15) into socksit.yaml. On disk that is
// indistinguishable from a deliberate FakeIP-router opt-in by the presence of the
// range alone, so the first attempt at reverting skipped exactly the installs it
// was meant to rescue — they stayed on the unverified Class E range.
const strandedByBadRelease = `proxy:
  address: 10.0.0.1
  port: 1080
mode: allowlist
bypass_cidrs:
  - 198.18.0.0/15
  - 127.0.0.0/8
  - 169.254.0.0/16
  - 224.0.0.0/4
  - 255.255.255.255/32
dns:
  fakeip_v4: 240.0.0.0/15
`

// A hand-made router setup: the bypass list is NOT the old default set.
const deliberateRouter = `proxy:
  address: 10.0.0.1
  port: 1080
mode: allowlist
bypass_cidrs:
  - 198.18.0.0/15
  - 127.0.0.0/8
dns:
  fakeip_v4: 240.0.0.0/15
`

func TestRevertsConfigsStrandedByBadRelease(t *testing.T) {
	c, err := Parse([]byte(strandedByBadRelease))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.DNS.FakeIPv4 != DefaultFakeIPv4 {
		t.Errorf("fake-ip = %q, want %q (the machine-written Class E must be undone)", c.DNS.FakeIPv4, DefaultFakeIPv4)
	}
	if c.bypasses(RouterFakeIPv4) {
		t.Errorf("the router range must be dropped from the bypass list, got %v", c.EffectiveBypassCIDRs())
	}
	if !sameCIDRSet(c.EffectiveBypassCIDRs(), DefaultBypassCIDRs) {
		t.Errorf("bypass list = %v, want the current defaults %v", c.EffectiveBypassCIDRs(), DefaultBypassCIDRs)
	}
}

func TestKeepsDeliberateRouterSetup(t *testing.T) {
	c, err := Parse([]byte(deliberateRouter))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.DNS.FakeIPv4 != AltFakeIPv4 {
		t.Errorf("a hand-made router setup must keep %s, got %q", AltFakeIPv4, c.DNS.FakeIPv4)
	}
	if !c.bypasses(RouterFakeIPv4) {
		t.Error("a hand-made router setup must keep bypassing the router range")
	}
}

func TestSameCIDRSet(t *testing.T) {
	if !sameCIDRSet([]string{"a/1", " b/2 "}, []string{"b/2", "a/1"}) {
		t.Error("order and spacing must not matter")
	}
	if sameCIDRSet([]string{"a/1"}, []string{"a/1", "b/2"}) {
		t.Error("different sets must not compare equal")
	}
}

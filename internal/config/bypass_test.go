package config

import (
	"net"
	"strings"
	"testing"
)

// routerSetup is the opt-in a user behind a FakeIP router applies: bypass the
// router's range and move our own fake-ip out of the way.
const routerSetup = `proxy:
  address: 10.0.0.1
  port: 1080
mode: allowlist
bypass_cidrs:
  - 198.18.0.0/15
  - 127.0.0.0/8
dns:
  fakeip_v4: 240.0.0.0/15
`

const plainSetup = `proxy:
  address: 10.0.0.1
  port: 1080
mode: allowlist
`

// TestDefaultsDoNotBypassRouterFakeIP pins the reversal: 198.18.0.0/15 is OUR
// fake-ip range by default, so it must stay inside the tunnel. Bypassing it by
// default forced everyone's fake-ip to move, which stranded cached addresses.
func TestDefaultsDoNotBypassRouterFakeIP(t *testing.T) {
	c := Default()
	if c.DNS.FakeIPv4 != "198.18.0.0/15" {
		t.Errorf("default fake-ip = %q, want 198.18.0.0/15", c.DNS.FakeIPv4)
	}
	if c.IsBypassed(net.ParseIP("198.18.0.5")) {
		t.Error("our own fake-ip range must not be bypassed by default")
	}
	for _, ip := range []string{"127.0.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255"} {
		if !c.IsBypassed(net.ParseIP(ip)) {
			t.Errorf("%s should be bypassed by default", ip)
		}
	}
	if err := func() error { c.Proxy.Address = "10.0.0.1"; return c.Validate() }(); err != nil {
		t.Errorf("defaults must validate, got %v", err)
	}
}

// TestRouterBypassBoundaries covers the opt-in case and the exact edges of
// 198.18.0.0/15 (198.18.0.0 – 198.19.255.255).
func TestRouterBypassBoundaries(t *testing.T) {
	c, err := Parse([]byte(routerSetup))
	if err != nil {
		t.Fatalf("router opt-in config must be valid, got %v", err)
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"198.18.0.0", true},      // first address
		{"198.18.255.255", true},  // inside
		{"198.19.0.0", true},      // inside (second /16)
		{"198.19.255.255", true},  // last address
		{"198.17.255.255", false}, // one below
		{"198.20.0.0", false},     // one above
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"240.0.0.1", false}, // the relocated fake-ip stays in the tunnel
	}
	for _, tc := range cases {
		if got := c.IsBypassed(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("IsBypassed(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if c.IsBypassed(nil) {
		t.Error("IsBypassed(nil) must be false")
	}
}

// TestBypassDefaultsAndOptOut: absent key = defaults, explicit empty = none,
// explicit list replaces the defaults.
func TestBypassDefaultsAndOptOut(t *testing.T) {
	old := ParseLenient([]byte(plainSetup))
	if len(old.EffectiveBypassCIDRs()) != len(DefaultBypassCIDRs) {
		t.Errorf("a config without bypass_cidrs must get the defaults, got %v", old.EffectiveBypassCIDRs())
	}

	off := ParseLenient([]byte(plainSetup + `bypass_cidrs: []
`))
	if got := off.EffectiveBypassCIDRs(); len(got) != 0 {
		t.Errorf("an explicit empty bypass_cidrs must disable the defaults, got %v", got)
	}
	if off.IsBypassed(net.ParseIP("127.0.0.1")) {
		t.Error("bypass must be off when the list is explicitly empty")
	}

	custom := ParseLenient([]byte(plainSetup + `bypass_cidrs:
  - 100.64.0.0/10
`))
	if !custom.IsBypassed(net.ParseIP("100.64.0.1")) {
		t.Error("a user-supplied bypass range must match")
	}
	if custom.IsBypassed(net.ParseIP("127.0.0.1")) {
		t.Error("an explicit list replaces the defaults")
	}
}

// TestClassEReversion: the short-lived release that moved everyone to Class E is
// undone on load — unless this install genuinely opted into the router setup.
func TestClassEReversion(t *testing.T) {
	stranded := ParseLenient([]byte(plainSetup + `dns:
  fakeip_v4: 240.0.0.0/15
`))
	if stranded.DNS.FakeIPv4 != DefaultFakeIPv4 {
		t.Errorf("Class E left over from the bad release must revert to %s, got %q", DefaultFakeIPv4, stranded.DNS.FakeIPv4)
	}

	router := ParseLenient([]byte(routerSetup))
	if router.DNS.FakeIPv4 != AltFakeIPv4 {
		t.Errorf("a deliberate router setup must keep %s, got %q", AltFakeIPv4, router.DNS.FakeIPv4)
	}

	custom := ParseLenient([]byte(plainSetup + `dns:
  fakeip_v4: 100.100.0.0/16
`))
	if custom.DNS.FakeIPv4 != "100.100.0.0/16" {
		t.Errorf("a custom fake-ip range must be preserved, got %q", custom.DNS.FakeIPv4)
	}
}

// TestBypassValidation: malformed CIDRs are rejected, and a fake-ip range that
// its own bypass list would black-hole is rejected with guidance.
func TestBypassValidation(t *testing.T) {
	c := Default()
	c.Proxy.Address = "10.0.0.1"
	c.BypassCIDRs = []string{"127.0.0.0/8", "not-a-cidr"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "bypass_cidrs") {
		t.Errorf("expected a bypass_cidrs CIDR error, got %v", err)
	}

	// Bypassing 198.18/15 while still using it as fake-ip is the trap the default
	// used to create; it must be refused, and the message must point at the fix.
	overlap := Default()
	overlap.Proxy.Address = "10.0.0.1"
	overlap.BypassCIDRs = []string{RouterFakeIPv4}
	err := overlap.Validate()
	if err == nil || !strings.Contains(err.Error(), "overlaps bypass_cidrs") {
		t.Fatalf("expected an overlap error, got %v", err)
	}
	if !strings.Contains(err.Error(), AltFakeIPv4) {
		t.Errorf("the error should recommend %s, got %v", AltFakeIPv4, err)
	}

	if _, err := Parse([]byte(routerSetup)); err != nil {
		t.Errorf("the documented router recipe must validate, got %v", err)
	}
}

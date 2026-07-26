package config

import (
	"net"
	"strings"
	"testing"
)

// TestIsBypassedBoundaries pins the FakeIP range edges: 198.18.0.0/15 spans
// 198.18.0.0 – 198.19.255.255, and the neighbours must NOT match.
func TestIsBypassedBoundaries(t *testing.T) {
	c := Default()
	cases := []struct {
		ip   string
		want bool
	}{
		{"198.18.0.0", true},      // first address of the range
		{"198.18.255.255", true},  // inside
		{"198.19.0.0", true},      // inside (second /16)
		{"198.19.255.255", true},  // last address of the range
		{"198.17.255.255", false}, // one below
		{"198.20.0.0", false},     // one above
		{"127.0.0.1", true},       // loopback
		{"169.254.1.1", true},     // link-local
		{"224.0.0.1", true},       // multicast
		{"255.255.255.255", true}, // broadcast
		{"8.8.8.8", false},        // ordinary Internet
		{"192.168.1.1", false},    // LAN is not bypassed (kept direct by other rules)
		{"240.0.0.1", false},      // our own fake-ip range must stay in the tunnel
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", tc.ip)
		}
		if got := c.IsBypassed(ip); got != tc.want {
			t.Errorf("IsBypassed(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if c.IsBypassed(nil) {
		t.Error("IsBypassed(nil) must be false")
	}
}

// TestBypassDefaultsAndOptOut covers backward compatibility: an old config with
// no bypass_cidrs key gets the defaults, while an explicit empty list disables.
func TestBypassDefaultsAndOptOut(t *testing.T) {
	old := ParseLenient([]byte("proxy:\n  address: 10.0.0.1\n  port: 1080\nmode: allowlist\n"))
	if len(old.EffectiveBypassCIDRs()) != len(DefaultBypassCIDRs) {
		t.Errorf("a config without bypass_cidrs must get the defaults, got %v", old.EffectiveBypassCIDRs())
	}
	if !old.IsBypassed(net.ParseIP("198.18.5.5")) {
		t.Error("router FakeIP range must be bypassed by default")
	}

	off := ParseLenient([]byte("proxy:\n  address: 10.0.0.1\n  port: 1080\nmode: allowlist\nbypass_cidrs: []\n"))
	if got := off.EffectiveBypassCIDRs(); len(got) != 0 {
		t.Errorf("an explicit empty bypass_cidrs must disable the defaults, got %v", got)
	}
	if off.IsBypassed(net.ParseIP("198.18.5.5")) {
		t.Error("bypass must be off when the list is explicitly empty")
	}

	custom := ParseLenient([]byte("proxy:\n  address: 10.0.0.1\n  port: 1080\nmode: allowlist\nbypass_cidrs:\n  - 100.64.0.0/10\n"))
	if !custom.IsBypassed(net.ParseIP("100.64.0.1")) {
		t.Error("a user-supplied bypass range must match")
	}
	if custom.IsBypassed(net.ParseIP("198.18.0.1")) {
		t.Error("an explicit list replaces the defaults")
	}
}

// TestFakeIPMigration verifies the legacy 198.18.0.0/15 fake-ip default is moved
// to the Class E range (it collided with router FakeIP), while a deliberate
// custom range is preserved.
func TestFakeIPMigration(t *testing.T) {
	if Default().DNS.FakeIPv4 != DefaultFakeIPv4 {
		t.Fatalf("Default fake-ip = %q, want %q", Default().DNS.FakeIPv4, DefaultFakeIPv4)
	}
	legacy := ParseLenient([]byte("proxy:\n  address: 10.0.0.1\nmode: allowlist\ndns:\n  fakeip_v4: " + LegacyFakeIPv4 + "\n"))
	if legacy.DNS.FakeIPv4 != DefaultFakeIPv4 {
		t.Errorf("legacy fake-ip must migrate to %s, got %q", DefaultFakeIPv4, legacy.DNS.FakeIPv4)
	}
	custom := ParseLenient([]byte("proxy:\n  address: 10.0.0.1\nmode: allowlist\ndns:\n  fakeip_v4: 100.100.0.0/16\n"))
	if custom.DNS.FakeIPv4 != "100.100.0.0/16" {
		t.Errorf("a custom fake-ip range must be preserved, got %q", custom.DNS.FakeIPv4)
	}
}

// TestBypassValidation checks the error paths: a malformed CIDR, and a fake-ip
// range that would be black-holed by its own bypass list.
func TestBypassValidation(t *testing.T) {
	c := Default()
	c.Proxy.Address = "10.0.0.1"
	c.BypassCIDRs = []string{"198.18.0.0/15", "not-a-cidr"}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "bypass_cidrs") {
		t.Errorf("expected a bypass_cidrs CIDR error, got %v", err)
	}

	overlap := Default()
	overlap.Proxy.Address = "10.0.0.1"
	overlap.DNS.FakeIPv4 = "198.18.0.0/15" // set directly: would be bypassed
	if err := overlap.Validate(); err == nil || !strings.Contains(err.Error(), "overlaps bypass_cidrs") {
		t.Errorf("expected an overlap error for a bypassed fake-ip range, got %v", err)
	}

	ok := Default()
	ok.Proxy.Address = "10.0.0.1"
	if err := ok.Validate(); err != nil {
		t.Errorf("defaults must validate, got %v", err)
	}
}

// TestBypassOverlapThroughLoadPath exercises the real load path (Parse =
// applyDefaults + Validate), where migration runs before validation:
//   - the legacy fake-ip value migrates and therefore parses fine;
//   - a *custom* range inside a bypass CIDR is rejected;
//   - unless the user disabled the bypass defaults.
func TestBypassOverlapThroughLoadPath(t *testing.T) {
	base := "proxy:\n  address: 10.0.0.1\n  port: 1080\nmode: allowlist\n"

	legacy, err := Parse([]byte(base + "dns:\n  fakeip_v4: " + LegacyFakeIPv4 + "\n"))
	if err != nil {
		t.Fatalf("legacy fake-ip must migrate and parse, got %v", err)
	}
	if legacy.DNS.FakeIPv4 != DefaultFakeIPv4 {
		t.Errorf("fake-ip after load = %q, want %q", legacy.DNS.FakeIPv4, DefaultFakeIPv4)
	}

	if _, err := Parse([]byte(base + "dns:\n  fakeip_v4: 198.18.5.0/24\n")); err == nil {
		t.Error("a custom fake-ip range inside a bypass CIDR must be rejected")
	} else if !strings.Contains(err.Error(), "overlaps bypass_cidrs") {
		t.Errorf("unexpected error: %v", err)
	}

	if _, err := Parse([]byte(base + "dns:\n  fakeip_v4: 198.18.5.0/24\nbypass_cidrs: []\n")); err != nil {
		t.Errorf("with bypass disabled the same range must be allowed, got %v", err)
	}
}

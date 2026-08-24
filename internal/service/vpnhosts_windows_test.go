//go:build windows

package service

import (
	"os"
	"path/filepath"
	"testing"

	"socksit/internal/config"
)

func TestHostFromEndpoint(t *testing.T) {
	cases := map[string]string{
		"vpn.example.com":                 "vpn.example.com",
		"VPN.Example.COM":                 "vpn.example.com",
		"vpn.example.com.":                "vpn.example.com",
		"gw.example.com:10443":            "gw.example.com",
		"https://gw.example.com:10443/":   "gw.example.com",
		"https://gw.example.com/remote/l": "gw.example.com",
		// An address literal never gets a fake-ip, so exempting it is noise.
		"10.0.0.1":      "",
		"10.0.0.1:443":  "",
		"[fd00::1]:443": "",
		// A display label, which is what HostName often holds.
		"Work VPN (Moscow)": "",
		"corp":              "",
		"":                  "",
	}
	for in, want := range cases {
		if got := hostFromEndpoint(in); got != want {
			t.Errorf("hostFromEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCiscoProfileHosts parses the shape AnyConnect actually writes: HostAddress
// carries the gateway, HostName is a label that admins routinely set to the
// gateway as well — so both are read, and shape decides what survives.
func TestCiscoProfileHosts(t *testing.T) {
	dir := t.TempDir()
	profile := `<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/">
  <ServerList>
    <HostEntry>
      <HostName>Head office</HostName>
      <HostAddress>vpn.example.com</HostAddress>
      <BackupServerList><HostAddress>vpnbackup.example.com</HostAddress></BackupServerList>
    </HostEntry>
    <HostEntry>
      <HostName>vpn3.example.com</HostName>
      <HostAddress>vpn3.example.com</HostAddress>
    </HostEntry>
  </ServerList>
</AnyConnectProfile>`
	if err := os.WriteFile(filepath.Join(dir, "corp.xml"), []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ciscoProfileHostsIn([]string{dir, filepath.Join(dir, "does-not-exist")})

	want := map[string]bool{"Head office": true, "vpn.example.com": true, "vpnbackup.example.com": true, "vpn3.example.com": true}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected value from the profile: %q", g)
		}
	}
	// The label is dropped only by the shape filter, so check the end result too.
	seen := map[string]bool{}
	for _, h := range got {
		if v := hostFromEndpoint(h); v != "" {
			seen[v] = true
		}
	}
	for _, h := range []string{"vpn.example.com", "vpnbackup.example.com", "vpn3.example.com"} {
		if !seen[h] {
			t.Errorf("%s must be exempted — a missed gateway breaks that VPN", h)
		}
	}
	if seen["head office"] {
		t.Error("a display label must not end up in the exemption list")
	}
}

func TestRasPhonebookHosts(t *testing.T) {
	dir := t.TempDir()
	pbk := "[Work]\r\nEncoding=1\r\nPhoneNumber=https://gw.example.com:10443/\r\nDevice=WAN Miniport (IKEv2)\r\n\r\n[Home]\r\nPhoneNumber=vpn2.example.com\r\n"
	path := filepath.Join(dir, "rasphone.pbk")
	if err := os.WriteFile(path, []byte(pbk), 0o600); err != nil {
		t.Fatal(err)
	}
	got := rasPhonebookHostsFrom(path)
	if len(got) != 2 {
		t.Fatalf("expected both entries, got %v", got)
	}
	if hostFromEndpoint(got[0]) != "gw.example.com" || hostFromEndpoint(got[1]) != "vpn2.example.com" {
		t.Errorf("phonebook entries did not reduce to hostnames: %v", got)
	}
	if rasPhonebookHostsFrom(filepath.Join(dir, "absent.pbk")) != nil {
		t.Error("a missing phonebook must be silent, not an error")
	}
}

// TestDetectedGatewaysSurviveAnEmptyDirectDomains: the exemption is a guard, not
// a preference. A user who clears direct_domains is switching off their own list,
// not asking SocksIt to break the machine's VPN client.
func TestDetectedGatewaysSurviveAnEmptyDirectDomains(t *testing.T) {
	c := config.Default()
	c.Proxy.Address = "10.0.0.1"
	c.DirectDomains = []string{}
	c.ExtraDirectDomains = []string{"vpn.example.com"}
	got := c.EffectiveDirectDomains()
	if len(got) != 1 || got[0] != "vpn.example.com" {
		t.Errorf("a detected gateway must stay exempt, got %v", got)
	}

	// And it is never written back to the file the user owns.
	c.DirectDomains = nil
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

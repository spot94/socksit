package config

import "testing"

func TestParseValidWithDefaults(t *testing.T) {
	y := `
proxy:
  address: 192.0.2.10
  port: 1080
apps:
  - chrome.exe
mode: allowlist
`
	c, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Coexistence != "" {
		t.Errorf("deprecated coexistence should be cleared on load, got %q", c.Coexistence)
	}
	if !c.KillSwitchOn() {
		t.Error("kill switch should default on")
	}
	if c.DNS.FakeIPv4 == "" || c.Control.ClashAPI == "" {
		t.Error("defaults for dns/control not applied")
	}
}

func TestParseRejectsUnknownKey(t *testing.T) {
	y := "proxy:\n  address: 1.2.3.4\n  port: 1\nmode: allowlist\ntypo_field: true\n"
	if _, err := Parse([]byte(y)); err == nil {
		t.Error("expected unknown-field rejection")
	}
}

func TestValidateErrors(t *testing.T) {
	cases := map[string]func(*Config){
		"empty address":        func(c *Config) { c.Proxy.Address = "" },
		"bad port":             func(c *Config) { c.Proxy.Port = 0; c.Proxy.Port = 70000 },
		"bad mode":             func(c *Config) { c.Mode = "nope" },
		"half auth":            func(c *Config) { c.Proxy.Username = "u" },
		"non-loopback control": func(c *Config) { c.Control.ClashAPI = "0.0.0.0:9797" },
		"bad fakeip":           func(c *Config) { c.DNS.FakeIPv4 = "not-a-cidr" },
		"bad direct subnet":    func(c *Config) { c.DirectSubnets = []string{"192.168.0.0/24", "nope"} },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := Default()
			c.Proxy.Address = "1.2.3.4"
			mut(c)
			if err := c.Validate(); err == nil {
				t.Errorf("%s: expected validation error", name)
			}
		})
	}
}

func TestValidateAcceptsGood(t *testing.T) {
	c := Default()
	c.Proxy.Address = "1.2.3.4"
	if err := c.Validate(); err != nil {
		t.Errorf("expected valid config, got %v", err)
	}
}

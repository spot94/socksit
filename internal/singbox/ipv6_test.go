package singbox

import (
	"testing"

	"socksit/internal/config"
)

// TestProxiedAppsCannotEscapeOverIPv6 guards a silent leak: the TUN carries no
// IPv6, so a proxied app that resolves AAAA reaches its destination outside the
// tunnel — unproxied, not covered by the kill-switch and absent from Statistics.
// AAAA must be refused for the proxied set, before the fake-ip routing rules.
func TestProxiedAppsCannotEscapeOverIPv6(t *testing.T) {
	c := config.Default()
	c.Proxy.Address = "10.0.0.1"
	c.Apps = []string{"claude.exe"}

	sb, err := Generate(c)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	firstFakeIP, rejects := -1, 0
	for i, r := range sb.DNS.Rules {
		switch {
		case r.Action == "reject" && contains(r.QueryType, "AAAA"):
			rejects++
			if firstFakeIP >= 0 {
				t.Error("AAAA refusal must come before the fake-ip routing rules")
			}
		case r.Server == tagFakeIP && firstFakeIP < 0:
			firstFakeIP = i
		}
	}
	if rejects == 0 {
		t.Fatalf("expected AAAA to be refused for the proxied apps, rules: %+v", sb.DNS.Rules)
	}
	if firstFakeIP < 0 {
		t.Error("expected the proxied apps to still resolve through fake-ip")
	}
	checkWithEngine(t, c)

	// blocklist: the proxied set is everything EXCEPT the listed apps, so the
	// refusal must be inverted rather than dropped.
	c.Mode = config.ModeBlocklist
	sb, err = Generate(c)
	if err != nil {
		t.Fatalf("generate blocklist: %v", err)
	}
	found := false
	for _, r := range sb.DNS.Rules {
		if r.Action == "reject" && contains(r.QueryType, "AAAA") && r.Invert {
			found = true
		}
	}
	if !found {
		t.Errorf("blocklist mode must refuse AAAA for everything except the listed apps: %+v", sb.DNS.Rules)
	}
	checkWithEngine(t, c)

	// No apps configured: nothing is proxied, so nothing should be refused.
	c.Mode = config.ModeAllowlist
	c.Apps = nil
	sb, err = Generate(c)
	if err != nil {
		t.Fatalf("generate empty: %v", err)
	}
	for _, r := range sb.DNS.Rules {
		if r.Action == "reject" {
			t.Errorf("no apps configured — nothing should be refused, got %+v", r)
		}
	}
}

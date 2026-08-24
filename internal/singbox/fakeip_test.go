package singbox

import (
	"testing"

	"socksit/internal/config"
)

// TestFakeIPForAllLookups pins the DNS fix. Selecting the fake-ip server by
// process never worked on Windows — the query is sent by the DNS Client service,
// not by the application — so proxied apps resolved through the local resolver:
// names leaked, and the addresses came from a resolver near the user rather than
// near the proxy (wrong CDN edge, split-horizon answers unreachable from it).
func TestFakeIPForAllLookups(t *testing.T) {
	c := config.Default()
	c.Proxy.Address = "10.0.0.1"
	c.Apps = []string{"claude.exe"}

	sb, err := Generate(c)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	rules := sb.DNS.Rules

	// A catch-all A rule, not a per-process one.
	var catchAll, perProcess int
	for _, r := range rules {
		if r.Server == tagFakeIP {
			if len(r.ProcessName) > 0 || len(r.ProcessPathRegex) > 0 {
				perProcess++
			} else if contains(r.QueryType, "A") {
				catchAll++
			}
		}
	}
	if catchAll != 1 {
		t.Errorf("expected exactly one catch-all fake-ip rule, got %d: %+v", catchAll, rules)
	}
	if perProcess != 0 {
		t.Errorf("per-process fake-ip rules must be gone, got %d", perProcess)
	}

	// Exemptions come first, or a fake-ip would win over them.
	idxSuffix, idxCatch := -1, -1
	for i, r := range rules {
		if len(r.DomainSuffix) > 0 && idxSuffix < 0 {
			idxSuffix = i
		}
		if r.Server == tagFakeIP && contains(r.QueryType, "A") {
			idxCatch = i
		}
	}
	if idxSuffix < 0 || idxSuffix > idxCatch {
		t.Errorf("mDNS/intranet suffixes must be exempted before the catch-all: %+v", rules)
	}
	// AAAA is refused globally: a per-process refusal would never match either.
	global := false
	for _, r := range rules {
		if r.Action == "reject" && contains(r.QueryType, "AAAA") && len(r.ProcessName) == 0 && len(r.ProcessPathRegex) == 0 {
			global = true
		}
	}
	if !global {
		t.Errorf("expected a global AAAA refusal: %+v", rules)
	}
	checkWithEngine(t, c)
}

// TestProxyHostnameNeverFakeIP: dialing the proxy through a fake address would
// break the tunnel outright, so its own name must resolve for real.
func TestProxyHostnameNeverFakeIP(t *testing.T) {
	c := config.Default()
	c.Proxy.Address = "proxy.corp.example"
	c.Apps = []string{"claude.exe"}

	sb, err := Generate(c)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	found := false
	for _, r := range sb.DNS.Rules {
		if r.Server == tagLocal && contains(r.Domain, "proxy.corp.example") {
			found = true
		}
	}
	if !found {
		t.Errorf("the proxy hostname must be exempted from fake-ip: %+v", sb.DNS.Rules)
	}
	checkWithEngine(t, c)

	// An IP proxy needs no exemption.
	c.Proxy.Address = "10.0.0.1"
	sb, _ = Generate(c)
	for _, r := range sb.DNS.Rules {
		if len(r.Domain) > 0 {
			t.Errorf("no domain exemption expected for an IP proxy: %+v", r)
		}
	}
}

// TestDirectDomainsOptOut: an explicit empty list exempts nothing.
func TestDirectDomainsOptOut(t *testing.T) {
	c := config.Default()
	c.Proxy.Address = "10.0.0.1"
	c.DNS.DirectDomains = []string{}
	sb, err := Generate(c)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, r := range sb.DNS.Rules {
		if len(r.DomainSuffix) > 0 {
			t.Errorf("no suffix exemption expected, got %+v", r)
		}
	}
	checkWithEngine(t, c)
}

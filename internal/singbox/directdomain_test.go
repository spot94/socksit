package singbox

import (
	"testing"

	"socksit/internal/config"
)

func ruleIdx(rules []RouteRule, pred func(RouteRule) bool) int {
	for i, r := range rules {
		if pred(r) {
			return i
		}
	}
	return -1
}

// TestDirectDomainsAreNeverProxied pins the exemption a per-process datapath
// otherwise cannot express. Keeping a name off fake-ip is not enough on its own:
// routing is by process, so a proxied app would still hand the address to the
// proxy. Real case: an endpoint whose anti-DDoS front end drops SYNs from the
// proxy's hosting IP while answering the same client directly.
func TestDirectDomainsAreNeverProxied(t *testing.T) {
	c := config.Default()
	c.Proxy.Address = "10.0.0.1"
	c.Apps = []string{"node.exe"}
	c.DirectDomains = []string{"agent-gw.example.com", ".corp.local"}

	sb, err := Generate(c)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// 1. off fake-ip
	dns := ruleIdx2(sb.DNS.Rules, func(r DNSRule) bool {
		return r.Server == tagLocal && contains(r.Domain, "agent-gw.example.com")
	})
	if dns < 0 {
		t.Errorf("the name must resolve for real, not to a fake-ip: %+v", sb.DNS.Rules)
	}

	// 2. routed direct, and BEFORE the app rule — otherwise node.exe wins
	direct := ruleIdx(sb.Route.Rules, func(r RouteRule) bool {
		return r.Outbound == tagDirect && contains(r.Domain, "agent-gw.example.com")
	})
	app := ruleIdx(sb.Route.Rules, func(r RouteRule) bool { return r.Outbound == tagProxy })
	if direct < 0 {
		t.Fatalf("expected a route rule sending the name direct: %+v", sb.Route.Rules)
	}
	if app >= 0 && direct > app {
		t.Errorf("the direct rule must precede the app rule (%d > %d)", direct, app)
	}

	// 3. a bare name covers itself and its subdomains; a dotted entry only the
	// latter. sing-box domain_suffix is a literal suffix, hence the explicit dot.
	r := sb.Route.Rules[direct]
	if !contains(r.DomainSuffix, ".agent-gw.example.com") {
		t.Errorf("a bare name must also cover subdomains: %+v", r)
	}
	if !contains(r.DomainSuffix, ".corp.local") || contains(r.Domain, ".corp.local") {
		t.Errorf("a dotted entry must stay suffix-only: %+v", r)
	}
	checkWithEngine(t, c)
}

// TestDirectDomainDefaultsKeepWindowsConnectivitySane: fake-ip is handed out
// machine-wide, and NCSI compares the answer for dns.msftncsi.com against a
// fixed address — a synthetic one makes Windows report no internet.
func TestDirectDomainDefaultsKeepWindowsConnectivitySane(t *testing.T) {
	c := config.Default()
	c.Proxy.Address = "10.0.0.1"
	c.Apps = []string{"claude.exe"}

	sb, err := Generate(c)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, want := range []string{".msftncsi.com", ".msftconnecttest.com", ".local"} {
		if ruleIdx2(sb.DNS.Rules, func(r DNSRule) bool {
			return r.Server == tagLocal && contains(r.DomainSuffix, want)
		}) < 0 {
			t.Errorf("%s must be exempt from fake-ip by default: %+v", want, sb.DNS.Rules)
		}
	}
}

// TestDirectDomainsEmptyDisables: an explicit empty list exempts nothing.
func TestDirectDomainsEmptyDisables(t *testing.T) {
	c := config.Default()
	c.Proxy.Address = "10.0.0.1"
	c.DirectDomains = []string{}

	sb, err := Generate(c)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, r := range sb.Route.Rules {
		if len(r.Domain) > 0 || len(r.DomainSuffix) > 0 {
			t.Errorf("no domain rule expected: %+v", r)
		}
	}
	for _, r := range sb.DNS.Rules {
		if len(r.DomainSuffix) > 0 {
			t.Errorf("no suffix exemption expected: %+v", r)
		}
	}
	checkWithEngine(t, c)
}

func ruleIdx2(rules []DNSRule, pred func(DNSRule) bool) int {
	for i, r := range rules {
		if pred(r) {
			return i
		}
	}
	return -1
}

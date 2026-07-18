package singbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"socksit/internal/config"
)

func baseCfg() *config.Config {
	c := config.Default()
	c.Proxy.Address = "192.0.2.10" // RFC 5737 documentation address
	c.Proxy.Port = 1080
	return c
}

// enginePath locates the staged sing-box binary so the generated config can be
// validated with `sing-box check`. Returns "" when unavailable (test skips the
// engine check but still asserts structure).
func enginePath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SOCKSIT_ENGINE"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	cand := filepath.Join("..", "..", "assets", "bin", "sing-box.exe")
	if _, err := os.Stat(cand); err == nil {
		abs, _ := filepath.Abs(cand)
		return abs
	}
	return ""
}

func checkWithEngine(t *testing.T, c *config.Config) {
	t.Helper()
	js, err := GenerateJSON(c)
	if err != nil {
		t.Fatalf("GenerateJSON: %v", err)
	}
	eng := enginePath(t)
	if eng == "" {
		t.Skip("sing-box engine not staged; skipping `sing-box check` validation")
	}
	if err := CheckBytes(eng, js); err != nil {
		t.Fatalf("generated config failed sing-box check: %v\n---\n%s", err, js)
	}
}

func findRoute(rules []RouteRule, pred func(RouteRule) bool) *RouteRule {
	for i := range rules {
		if pred(rules[i]) {
			return &rules[i]
		}
	}
	return nil
}

func TestAllowlistGreedy(t *testing.T) {
	c := baseCfg()
	c.Mode = config.ModeAllowlist
	c.Apps = []string{"chrome.exe", `C:\Games\game.exe`}

	sb, err := Generate(c)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if sb.Inbounds[0].RouteAddress != nil {
		t.Errorf("greedy: route_address must be empty (full capture), got %v", sb.Inbounds[0].RouteAddress)
	}
	if sb.Inbounds[0].StrictRoute {
		t.Error("greedy: strict_route must be off (full capture hijacks DNS naturally)")
	}
	if sb.Route.Final != tagDirect {
		t.Errorf("allowlist: route final = %q, want %q", sb.Route.Final, tagDirect)
	}
	if sb.Route.DefaultDomainResolver == nil {
		t.Error("missing default_domain_resolver (required since sing-box 1.12)")
	}
	pr := findRoute(sb.Route.Rules, func(r RouteRule) bool { return len(r.ProcessPathRegex) > 0 })
	if pr == nil || pr.Outbound != tagProxy {
		t.Errorf("expected a process-path-regex rule routing to %q", tagProxy)
	} else {
		if len(pr.ProcessPathRegex) != 2 {
			t.Errorf("expected 2 app regexes (name + path), got %d", len(pr.ProcessPathRegex))
		}
		for _, rx := range pr.ProcessPathRegex {
			if !strings.HasPrefix(rx, "(?i)") {
				t.Errorf("app regex must be case-insensitive, got %q", rx)
			}
		}
	}
	// A path-independent process_name rule must also route the bare-name app to
	// the proxy, so it matches even when the full process path can't be read.
	if nr := findRoute(sb.Route.Rules, func(r RouteRule) bool { return len(r.ProcessName) > 0 }); nr == nil || nr.Outbound != tagProxy {
		t.Errorf("expected a process_name rule routing to %q", tagProxy)
	} else if len(nr.ProcessName) != 1 || nr.ProcessName[0] != "chrome.exe" {
		t.Errorf("expected process_name [chrome.exe], got %v", nr.ProcessName)
	}
	if r := findRoute(sb.Route.Rules, func(r RouteRule) bool { return len(r.IPCIDR) > 0 }); r == nil || r.Outbound != tagDirect {
		t.Error("expected an anti-loop ip_cidr rule to direct")
	}
	if sb.DNS.Final != tagLocal {
		t.Errorf("allowlist: dns final = %q, want %q", sb.DNS.Final, tagLocal)
	}
	if len(sb.DNS.Rules) == 0 || sb.DNS.Rules[0].Server != tagFakeIP {
		t.Error("allowlist: expected app DNS rule routing to fake-ip")
	}
	checkWithEngine(t, c)
}

func TestBlocklistGreedyWithAuth(t *testing.T) {
	c := baseCfg()
	c.Mode = config.ModeBlocklist
	c.Apps = []string{"foo.exe"}
	c.Proxy.Username = "user"
	c.Proxy.Password = "pass"

	sb, err := Generate(c)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if sb.Inbounds[0].RouteAddress != nil {
		t.Errorf("greedy: route_address must be empty, got %v", sb.Inbounds[0].RouteAddress)
	}
	if sb.Inbounds[0].StrictRoute {
		t.Error("greedy: strict_route must be off (full capture hijacks DNS naturally)")
	}
	if sb.Route.Final != tagProxy {
		t.Errorf("blocklist: route final = %q, want %q", sb.Route.Final, tagProxy)
	}
	if r := findRoute(sb.Route.Rules, func(r RouteRule) bool { return len(r.ProcessPathRegex) > 0 }); r == nil || r.Outbound != tagDirect {
		t.Errorf("blocklist: listed process should route to %q", tagDirect)
	}
	if sb.Outbounds[0].Username != "user" || sb.Outbounds[0].Password != "pass" {
		t.Error("proxy outbound should carry username/password")
	}
	if sb.DNS.Final != tagLocal {
		t.Errorf("blocklist: dns final = %q, want %q (fake-ip cannot be the default server)", sb.DNS.Final, tagLocal)
	}
	if len(sb.DNS.Rules) == 0 || !sb.DNS.Rules[0].Invert || sb.DNS.Rules[0].Server != tagFakeIP {
		t.Error("blocklist: expected an inverted app DNS rule routing non-listed processes to fake-ip")
	}
	checkWithEngine(t, c)
}

func TestAllowlistEmptyApps(t *testing.T) {
	c := baseCfg()
	c.Mode = config.ModeAllowlist
	c.Apps = nil

	sb, err := Generate(c)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if r := findRoute(sb.Route.Rules, func(r RouteRule) bool { return len(r.ProcessPathRegex) > 0 }); r != nil {
		t.Error("empty allowlist should emit no process rules")
	}
	checkWithEngine(t, c)
}

func TestDirectSubnets(t *testing.T) {
	c := baseCfg()
	c.Mode = config.ModeAllowlist
	c.Apps = []string{"chrome.exe"}
	c.DirectSubnets = []string{"192.168.1.0/24", "172.16.0.0/16"}

	sb, err := Generate(c)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	r := findRoute(sb.Route.Rules, func(r RouteRule) bool {
		return len(r.IPCIDR) == 2 && r.IPCIDR[0] == "192.168.1.0/24" && r.Outbound == tagDirect
	})
	if r == nil {
		t.Error("expected a bypass rule routing the direct_subnets to direct")
	}
	checkWithEngine(t, c)
}

func TestInvalidConfigRejected(t *testing.T) {
	c := baseCfg()
	c.Proxy.Address = ""
	if _, err := Generate(c); err == nil {
		t.Error("expected error for empty proxy address")
	}
}

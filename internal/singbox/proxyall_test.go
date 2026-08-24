package singbox

import (
	"testing"

	"socksit/internal/config"
)

// TestProxyAllIgnoresAppList: with the local "proxy all traffic" switch on,
// everything is routed to the proxy and the app list plays no part — while the
// bypass/direct rules still keep LAN and excluded ranges out of the tunnel.
func TestProxyAllIgnoresAppList(t *testing.T) {
	c := config.Default()
	c.Proxy.Address = "10.0.0.1"
	c.Apps = []string{"claude.exe"}
	c.DirectSubnets = []string{"192.168.0.0/16"}
	on := true
	c.ProxyAll = &on

	sb, err := Generate(c)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if sb.Route.Final != tagProxy {
		t.Errorf("route final = %q, want %q", sb.Route.Final, tagProxy)
	}
	for _, r := range sb.Route.Rules {
		if len(r.ProcessName) > 0 || len(r.ProcessPathRegex) > 0 {
			t.Errorf("the app list must be ignored, found a per-process rule: %+v", r)
		}
	}
	// LAN and the bypass ranges must still escape the proxy.
	var direct int
	for _, r := range sb.Route.Rules {
		if r.Outbound == tagDirect {
			direct++
		}
	}
	if direct == 0 {
		t.Error("expected direct rules (private/bypass/direct_subnets) to survive")
	}
	// v4-only datapath: nothing may resolve AAAA when everything is proxied.
	found := false
	for _, r := range sb.DNS.Rules {
		if r.Action == "reject" && contains(r.QueryType, "AAAA") && len(r.ProcessName) == 0 && len(r.ProcessPathRegex) == 0 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a global AAAA refusal, rules: %+v", sb.DNS.Rules)
	}
	checkWithEngine(t, c)

	// Off (the default) restores per-app routing.
	off := false
	c.ProxyAll = &off
	sb, err = Generate(c)
	if err != nil {
		t.Fatalf("generate off: %v", err)
	}
	if sb.Route.Final != tagDirect {
		t.Errorf("with the switch off, allowlist mode must end in %q", tagDirect)
	}
	if !hasRouteProcessRule(sb.Route.Rules) {
		t.Error("with the switch off, per-app rules must come back")
	}
}

func hasRouteProcessRule(rules []RouteRule) bool {
	for _, r := range rules {
		if len(r.ProcessName) > 0 || len(r.ProcessPathRegex) > 0 {
			return true
		}
	}
	return false
}

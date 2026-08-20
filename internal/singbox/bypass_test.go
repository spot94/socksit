package singbox

import (
	"encoding/json"
	"testing"

	"socksit/internal/config"
)

// TestBypassRouteExclusions verifies the bypass ranges are emitted as TUN
// route-exclusions (so they never enter the tunnel) AND as a direct route rule
// (the safety net), and that the fake-ip range is not excluded.
func TestBypassRouteExclusions(t *testing.T) {
	c := config.Default()
	c.Proxy.Address = "10.0.0.1"
	c.Apps = []string{"chrome.exe"}

	sb, err := Generate(c)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	excl := sb.Inbounds[0].RouteExcludeAddress
	if contains(excl, config.RouterFakeIPv4) {
		t.Errorf("the router FakeIP range is our own fake-ip by default — it must NOT be excluded, got %v", excl)
	}
	for _, want := range config.DefaultBypassCIDRs {
		if !contains(excl, want) {
			t.Errorf("missing default bypass %q in route exclusions %v", want, excl)
		}
	}
	if contains(excl, c.DNS.FakeIPv4) {
		t.Errorf("our own fake-ip range %q must NOT be excluded", c.DNS.FakeIPv4)
	}

	// Safety-net rule: bypass CIDRs routed to direct, never to the proxy.
	found := false
	for _, r := range sb.Route.Rules {
		if r.Outbound == tagDirect && contains(r.IPCIDR, "127.0.0.0/8") {
			found = true
		}
	}
	if !found {
		t.Error("expected a route rule sending the bypass ranges to the direct outbound")
	}

	// The emitted JSON must carry the sing-box key name.
	js, err := Marshal(sb)
	if err != nil {
		t.Fatal(err)
	}
	var probe struct {
		Inbounds []struct {
			Exclude []string `json:"route_exclude_address"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(js, &probe); err != nil {
		t.Fatal(err)
	}
	if len(probe.Inbounds) == 0 || !contains(probe.Inbounds[0].Exclude, "127.0.0.0/8") {
		t.Errorf("route_exclude_address missing in the generated JSON:\n%s", js)
	}

	// Opt-in (FakeIP router): the router range is excluded only once asked for,
	// together with moving our own fake-ip out of the way.
	c.BypassCIDRs = append([]string{config.RouterFakeIPv4}, config.DefaultBypassCIDRs...)
	c.DNS.FakeIPv4 = config.AltFakeIPv4
	sbRouter, err := Generate(c)
	if err != nil {
		t.Fatalf("router opt-in generate: %v", err)
	}
	if !contains(sbRouter.Inbounds[0].RouteExcludeAddress, config.RouterFakeIPv4) {
		t.Errorf("opt-in must exclude %s, got %v", config.RouterFakeIPv4, sbRouter.Inbounds[0].RouteExcludeAddress)
	}
	checkWithEngine(t, c)
}

// TestBypassDisabled: an explicit empty list emits no exclusions (opt-out).
func TestBypassDisabled(t *testing.T) {
	c := config.Default()
	c.Proxy.Address = "10.0.0.1"
	c.BypassCIDRs = []string{}

	sb, err := Generate(c)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(sb.Inbounds[0].RouteExcludeAddress) != 0 {
		t.Errorf("expected no exclusions when bypass is disabled, got %v", sb.Inbounds[0].RouteExcludeAddress)
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

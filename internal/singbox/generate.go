package singbox

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"

	"socksit/internal/config"
)

// Engine tags used throughout the generated config.
const (
	tagFakeIP = "dns-fakeip"
	tagLocal  = "dns-local"
	tagProxy  = "proxy"
	tagDirect = "direct"
	tagTUN    = "tun-in"

	// AdapterName is the fixed Wintun adapter name (R14) — unique so SocksIt can
	// find and reconcile a stale adapter after a hard kill, and so it coexists
	// with another engine instance.
	AdapterName = "socksit"
)

// Generate builds a sing-box Config (v1.12+ schema) from a SocksIt config.
// The output is expected to pass `sing-box check` (asserted by the tests).
func Generate(c *config.Config) (*Config, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	apps := c.EffectiveApps() // in override-managed mode this unions user + feed apps
	regexes := appRegexes(apps)
	names := appNames(apps)
	allow := c.Mode == config.ModeAllowlist

	out := &Config{
		Log: &Log{Level: "warn", Timestamp: true}, // warn: avoid per-connection INFO log bloat
		// IPv4-only datapath: the TUN has no IPv6 address (below), so v6 is not
		// carried through the tunnel and stays native — otherwise dual-stack hosts
		// (yandex, google) get RESET when the browser tries v6 through a TUN whose
		// direct outbound can't dial v6. fake-ip is v4-only to match.
		DNS: &DNS{
			Servers: []DNSServer{
				{Type: "fakeip", Tag: tagFakeIP, Inet4Range: c.DNS.FakeIPv4},
				{Type: "local", Tag: tagLocal},
			},
			IndependentCache: true,
		},
		Inbounds: []Inbound{{
			Type:          "tun",
			Tag:           tagTUN,
			InterfaceName: AdapterName,
			Address:       []string{"172.19.0.1/30"}, // IPv4-only: don't capture v6 (stays native)
			MTU:           9000,
			AutoRoute:     true,
			StrictRoute:   false,    // full capture: DNS is hijacked naturally, no strict_route needed
			Stack:         "system", // KTD2: system stack (gVisor breaks Windows process matching)
		}},
		Outbounds: []Outbound{
			proxyOutbound(c),
			{Type: "direct", Tag: tagDirect},
		},
		Route: &Route{
			AutoDetectInterface:   true,
			DefaultDomainResolver: &DomainResolver{Server: tagLocal}, // required since 1.12
			Final:                 tagDirect,
		},
		Experimental: &Experimental{ClashAPI: &ClashAPI{ExternalController: c.Control.ClashAPI}},
	}

	// Single mode: full-capture (auto_route with no route_address). The default
	// route enters the TUN, DNS is hijacked, fake-ip is assigned, and the route
	// rules below decide proxy vs direct per process. (The "polite" fake-ip-CIDR-only
	// mode was removed: it cannot intercept DNS, so it never proxied.)

	// DNS routing: the proxied set resolves through fake-ip; everyone else via
	// local. fake-ip cannot be the default/final DNS server, so final is always
	// local and blocklist selects the proxied set by inverting the app match.
	out.DNS.Final = tagLocal
	if allow {
		// The proxied set resolves through fake-ip. Match by name AND by path so a
		// process whose full path can't be read (sandboxed child) still qualifies.
		if len(names) > 0 {
			out.DNS.Rules = append(out.DNS.Rules, DNSRule{ProcessName: names, Action: "route", Server: tagFakeIP})
		}
		if len(regexes) > 0 {
			out.DNS.Rules = append(out.DNS.Rules, DNSRule{ProcessPathRegex: regexes, Action: "route", Server: tagFakeIP})
		}
	} else if len(regexes) > 0 {
		// blocklist: everything EXCEPT the listed set resolves via fake-ip.
		out.DNS.Rules = append(out.DNS.Rules, DNSRule{ProcessPathRegex: regexes, Invert: true, Action: "route", Server: tagFakeIP})
	}

	// Route rules: sniff + DNS hijack, anti-loop to the proxy, private direct,
	// then the per-process rule.
	rules := []RouteRule{
		{Action: "sniff"},
		{Protocol: "dns", Action: "hijack-dns"},
		antiLoopRule(c.Proxy.Address),
		{IPIsPrivate: true, Action: "route", Outbound: tagDirect},
	}
	// User-chosen bypass subnets always go direct (before the per-app rule).
	if subnets := trimAll(c.EffectiveSubnets()); len(subnets) > 0 {
		rules = append(rules, RouteRule{IPCIDR: subnets, Action: "route", Outbound: tagDirect})
	}
	appOutbound := tagProxy
	if !allow {
		// blocklist: listed apps go direct, everything else is proxied.
		appOutbound = tagDirect
		out.Route.Final = tagProxy
	}
	// Match the listed apps by name AND by path. process_name is path-independent,
	// so it still catches processes whose full path sing-box cannot read (e.g.
	// sandboxed Electron child processes) — process_path_regex alone misses those
	// and they leak to the route's default outbound.
	if len(names) > 0 {
		rules = append(rules, RouteRule{ProcessName: names, Action: "route", Outbound: appOutbound})
	}
	if len(regexes) > 0 {
		rules = append(rules, RouteRule{ProcessPathRegex: regexes, Action: "route", Outbound: appOutbound})
	}
	out.Route.Rules = rules

	return out, nil
}

// Marshal renders a config to indented JSON bytes.
func Marshal(c *Config) ([]byte, error) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal sing-box config: %w", err)
	}
	return append(b, '\n'), nil
}

// GenerateJSON is the convenience path: SocksIt config -> JSON bytes.
func GenerateJSON(c *config.Config) ([]byte, error) {
	sb, err := Generate(c)
	if err != nil {
		return nil, err
	}
	return Marshal(sb)
}

func proxyOutbound(c *config.Config) Outbound {
	o := Outbound{
		Type:       "socks",
		Tag:        tagProxy,
		Server:     c.Proxy.Address,
		ServerPort: c.Proxy.Port,
		Version:    "5",
	}
	if c.Proxy.Username != "" {
		o.Username = c.Proxy.Username
		o.Password = c.Proxy.Password
	}
	return o
}

// antiLoopRule keeps traffic to the proxy server itself off the TUN. If the
// address is an IP we pin a /32 or /128; otherwise we match the domain.
func antiLoopRule(addr string) RouteRule {
	if ip := net.ParseIP(addr); ip != nil {
		bits := "/32"
		if ip.To4() == nil {
			bits = "/128"
		}
		return RouteRule{IPCIDR: []string{addr + bits}, Action: "route", Outbound: tagDirect}
	}
	return RouteRule{Domain: []string{addr}, Action: "route", Outbound: tagDirect}
}

// appRegexes turns each app entry into a case-insensitive process_path_regex.
// Windows process/file names are case-insensitive, but sing-box process_name
// matching is case-sensitive; matching the path with (?i) restores expected
// behaviour. A bare name (chrome.exe) matches that executable in any directory;
// a full path matches exactly. All entries go into one array, so the rule
// OR-matches — and an invert (blocklist) correctly means "none of these".
func appRegexes(apps []string) []string {
	var out []string
	for _, a := range apps {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if strings.ContainsAny(a, `\/`) {
			out = append(out, `(?i)^`+regexp.QuoteMeta(a)+`$`) // full path, exact (any case)
		} else {
			out = append(out, `(?i)(?:^|[\\/])`+regexp.QuoteMeta(a)+`$`) // basename in any directory
		}
	}
	return out
}

// appNames returns the bare process names (entries without a path separator).
// These are matched with process_name, which is path-independent: it still
// catches a process whose full image path sing-box cannot read (e.g. a sandboxed
// Electron child process), where process_path_regex silently misses and the
// connection leaks to the route's default outbound. Windows image names are
// case-consistent, so exact-name matching is reliable in practice.
func appNames(apps []string) []string {
	var out []string
	for _, a := range apps {
		a = strings.TrimSpace(a)
		if a == "" || strings.ContainsAny(a, `\/`) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// trimAll trims each entry and drops empties.
func trimAll(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

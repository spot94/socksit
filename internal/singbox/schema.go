// Package singbox generates and validates a sing-box config.json (v1.12+ schema)
// from a SocksIt config. Only the subset of the sing-box schema that SocksIt
// emits is modeled here; the emitted shapes are exercised by the package tests
// (which validate the output with `sing-box check`).
package singbox

// Config is the top-level sing-box config.json.
type Config struct {
	Log          *Log          `json:"log,omitempty"`
	DNS          *DNS          `json:"dns,omitempty"`
	Inbounds     []Inbound     `json:"inbounds"`
	Outbounds    []Outbound    `json:"outbounds"`
	Route        *Route        `json:"route"`
	Experimental *Experimental `json:"experimental,omitempty"`
}

type Log struct {
	Level     string `json:"level"`
	Timestamp bool   `json:"timestamp"`
}

type DNS struct {
	Servers          []DNSServer `json:"servers"`
	Rules            []DNSRule   `json:"rules,omitempty"`
	Final            string      `json:"final,omitempty"`
	IndependentCache bool        `json:"independent_cache,omitempty"`
}

type DNSServer struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Inet4Range string `json:"inet4_range,omitempty"`
}

type DNSRule struct {
	ProcessName      []string `json:"process_name,omitempty"`
	ProcessPathRegex []string `json:"process_path_regex,omitempty"`
	Invert           bool     `json:"invert,omitempty"`
	Action           string   `json:"action"`
	Server           string   `json:"server,omitempty"`
}

type Inbound struct {
	Type          string   `json:"type"`
	Tag           string   `json:"tag"`
	InterfaceName string   `json:"interface_name,omitempty"`
	Address       []string `json:"address,omitempty"`
	MTU           int      `json:"mtu,omitempty"`
	AutoRoute     bool     `json:"auto_route"`
	StrictRoute   bool     `json:"strict_route"`
	Stack         string   `json:"stack,omitempty"`
	RouteAddress  []string `json:"route_address,omitempty"`
}

type Outbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
	Version    string `json:"version,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
}

type Route struct {
	AutoDetectInterface   bool            `json:"auto_detect_interface"`
	DefaultDomainResolver *DomainResolver `json:"default_domain_resolver,omitempty"`
	Rules                 []RouteRule     `json:"rules"`
	Final                 string          `json:"final"`
}

type DomainResolver struct {
	Server string `json:"server"`
}

type RouteRule struct {
	Action           string   `json:"action"`
	Protocol         string   `json:"protocol,omitempty"`
	IPCIDR           []string `json:"ip_cidr,omitempty"`
	IPIsPrivate      bool     `json:"ip_is_private,omitempty"`
	Domain           []string `json:"domain,omitempty"`
	ProcessName      []string `json:"process_name,omitempty"`
	ProcessPathRegex []string `json:"process_path_regex,omitempty"`
	Outbound         string   `json:"outbound,omitempty"`
}

type Experimental struct {
	ClashAPI *ClashAPI `json:"clash_api,omitempty"`
}

type ClashAPI struct {
	ExternalController string `json:"external_controller"`
}

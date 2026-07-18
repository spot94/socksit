// Package config defines the SocksIt user-facing YAML configuration and its
// validation. This is the WHAT the user edits; internal/singbox turns it into a
// sing-box config.json (the HOW the engine consumes).
package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Mode selects how the app list is interpreted.
const (
	ModeAllowlist = "allowlist" // only listed apps go through the proxy
	ModeBlocklist = "blocklist" // everything goes through the proxy except listed apps
)

// Merge modes for the managed-config feed.
const (
	MergeReplace  = "replace"  // remote config fully replaces the local one (default)
	MergeOverride = "override" // remote overrides only specified fields; app lists union
)

// Config is the parsed socksit.yaml.
type Config struct {
	Proxy Proxy    `yaml:"proxy"`
	Apps  []string `yaml:"apps"`
	// DirectSubnets are destination CIDRs that always bypass the proxy (go
	// direct), even for proxied apps — e.g. LAN ranges 192.168.1.0/24,
	// 172.16.0.0/16. Private ranges are already direct via ip_is_private; this
	// is for arbitrary user-chosen subnets (most useful in greedy mode).
	DirectSubnets []string `yaml:"direct_subnets"`
	Mode          string   `yaml:"mode"`
	// Coexistence is deprecated: the single capture mode makes it meaningless. It
	// is still accepted (so old files parse) but cleared on load and never emitted.
	Coexistence string `yaml:"coexistence,omitempty"`
	// KillSwitch true (default) = proxied apps are cut off while the tunnel is
	// down (per-app, via fake-ip unreachability). false = fail-open (proxied
	// apps fall back to direct). Consumed by the supervisor (netstate), not the
	// generated engine config — see plan KTD4.
	KillSwitch *bool `yaml:"kill_switch"`
	// ShowTray controls the notification-area icon. true (default) = while the
	// service is installed it keeps a tray running; false = no tray is launched
	// and a running one exits. Consumed by the service tray-keeper and the tray
	// itself, not the engine. See internal/service/traykeeper_windows.go.
	ShowTray *bool   `yaml:"show_tray"`
	DNS      DNS     `yaml:"dns"`
	Control  Control `yaml:"control"`
	Update   Update  `yaml:"update"`
	// ConfigSource optionally pulls this config from a URL (managed config). It is
	// a client-local policy and is preserved across remote fetches (a fetched
	// config cannot change it), so managed mode can't lock or unlock itself.
	ConfigSource ConfigSource `yaml:"config_source"`
	// ManagedApps is the app list contributed by the managed feed in "override"
	// merge mode. It is maintained by the service (mirrors the remote's apps) and
	// is combined with the user's own Apps for the effective routing set — see
	// EffectiveApps. Not meant to be hand-edited. Empty/absent in replace mode.
	ManagedApps []string `yaml:"managed_apps,omitempty"`
}

// ConfigSource describes an optional remote config feed. Because a remote config
// decides where traffic goes (proxy address, apps, direct subnets), it is
// signature-verified by default (Ed25519, same key as updates).
type ConfigSource struct {
	// URL of the config YAML; empty = use the local config (default).
	URL string `yaml:"url"`
	// Interval is a Go duration between refreshes (min 1m); also fetched on start.
	Interval string `yaml:"interval"`
	// Signed requires a matching <url>.sig; true (default) is strongly recommended.
	Signed *bool `yaml:"signed"`
	// Merge selects how the fetched config is applied: "replace" (default) swaps
	// the whole local config for the remote one; "override" applies only the fields
	// the remote actually specifies and keeps local values for the rest, and unions
	// the app lists (remote apps + the user's own apps). See MergeMode/EffectiveApps.
	Merge string `yaml:"merge,omitempty"`
	// PubKey is the base64 Ed25519 public key that verifies the feed's signature.
	// It is provisioned by the operator (NOT the app author): each deployment runs
	// its own signed config channel with its own key. Generate a pair with
	// `mksign genkey`, put the public half here, sign configs with the private half.
	// It is preserved across remote fetches, so a hostile server can't replace it.
	PubKey string `yaml:"pubkey"`
}

// Update modes.
const (
	UpdateOff    = "off"
	UpdateNotify = "notify"
	UpdateAuto   = "auto"
)

// Update controls in-app update checks. Trust is anchored on an Ed25519-signed
// manifest (public key compiled into the binary), so the endpoint/transport are
// untrusted. See docs/update-design.md.
type Update struct {
	// Endpoint is the base URL of the release channel; empty = updates disabled.
	// GitHub: https://github.com/<owner>/<repo>/releases/latest/download
	Endpoint string `yaml:"endpoint"`
	// Channel selects the manifest name (stable -> manifest.json, else manifest-<channel>.json).
	Channel string `yaml:"channel"`
	// Mode: off | notify | auto.
	Mode string `yaml:"mode"`
	// CheckInterval is a Go duration, e.g. "24h" (min 1h).
	CheckInterval string `yaml:"check_interval"`
	// Proxy: "" (direct) | "system" | "use-socks" | "socks5://host:port" | "http://host:port".
	Proxy string `yaml:"proxy"`
}

// Proxy is the upstream SOCKS5 server.
type Proxy struct {
	Address  string `yaml:"address"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// UDP enables UDP ASSOCIATE on the outbound. Defaults to true; if the server
	// lacks UDP the engine simply has no UDP path (see plan R13).
	UDP *bool `yaml:"udp"`
}

// DNS carries the fake-ip range for the (IPv4-only) datapath.
type DNS struct {
	FakeIPv4 string `yaml:"fakeip_v4"`
	// FakeIPv6 is deprecated: the datapath is IPv4-only (the TUN has no v6
	// address, so v6 stays native). Still accepted so old files parse, but it is
	// cleared on load and never used or re-emitted.
	FakeIPv6 string `yaml:"fakeip_v6,omitempty"`
}

// Control is the local management surface.
type Control struct {
	// ClashAPI is the engine's Clash API listen address (loopback only). Used by
	// the stats window. Must not be a non-loopback address.
	ClashAPI string `yaml:"clash_api"`
}

// Default returns a config populated with the first-run defaults: empty
// allowlist (nothing proxied until the user adds apps), greedy capture,
// kill-switch on.
func Default() *Config {
	on := true
	udp := true
	tray := true
	signed := true
	return &Config{
		Proxy:      Proxy{Port: 1080, UDP: &udp},
		Apps:       []string{},
		Mode:       ModeAllowlist,
		KillSwitch: &on,
		ShowTray:   &tray,
		DNS:        DNS{FakeIPv4: "198.18.0.0/15"},
		Control:    Control{ClashAPI: "127.0.0.1:9797"},
		Update: Update{
			Endpoint:      "https://github.com/spot94/socksit/releases/latest/download",
			Channel:       "stable",
			Mode:          UpdateNotify,
			CheckInterval: "24h",
			Proxy:         "use-socks",
		},
		ConfigSource: ConfigSource{Interval: "1h", Signed: &signed},
	}
}

// ConfigManaged reports whether the config is pulled from a remote URL.
func (c *Config) ConfigManaged() bool { return strings.TrimSpace(c.ConfigSource.URL) != "" }

// ConfigSigned reports the effective signature requirement (default true).
func (c *Config) ConfigSigned() bool { return c.ConfigSource.Signed == nil || *c.ConfigSource.Signed }

// MergeMode reports the effective managed-config merge mode (default replace).
func (c *Config) MergeMode() string {
	if strings.EqualFold(strings.TrimSpace(c.ConfigSource.Merge), MergeOverride) {
		return MergeOverride
	}
	return MergeReplace
}

// EffectiveApps is the app list the engine actually routes. Normally it is just
// Apps; under a managed feed in "override" mode it is the union of the user's own
// Apps and the feed-provided ManagedApps (case-insensitive dedupe, user first).
func (c *Config) EffectiveApps() []string {
	if c.ConfigManaged() && c.MergeMode() == MergeOverride {
		return dedupeApps(c.Apps, c.ManagedApps)
	}
	return c.Apps
}

// dedupeApps concatenates app lists dropping blanks and case-insensitive
// duplicates, preserving first-seen order.
func dedupeApps(lists ...[]string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, list := range lists {
		for _, a := range list {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			k := strings.ToLower(a)
			if !seen[k] {
				seen[k] = true
				out = append(out, a)
			}
		}
	}
	return out
}

// ConfigEvery is the effective refresh interval (default 1h, min 1m).
func (c *Config) ConfigEvery() time.Duration {
	d, err := time.ParseDuration(c.ConfigSource.Interval)
	if err != nil {
		return time.Hour
	}
	if d < time.Minute {
		return time.Minute
	}
	return d
}

// UpdatesEnabled reports whether periodic update checks should run.
func (c *Config) UpdatesEnabled() bool {
	return strings.TrimSpace(c.Update.Endpoint) != "" && c.Update.Mode != "" && c.Update.Mode != UpdateOff
}

// CheckEvery is the effective check interval (default 24h, min 1h).
func (c *Config) CheckEvery() time.Duration {
	d, err := time.ParseDuration(c.Update.CheckInterval)
	if err != nil {
		return 24 * time.Hour
	}
	if d < time.Hour {
		return time.Hour
	}
	return d
}

// KillSwitchOn reports the effective kill-switch setting (default true).
func (c *Config) KillSwitchOn() bool { return c.KillSwitch == nil || *c.KillSwitch }

// ShowTrayEnabled reports the effective tray setting (default true, so configs
// written before this option keep showing the tray).
func (c *Config) ShowTrayEnabled() bool { return c.ShowTray == nil || *c.ShowTray }

// UDPEnabled reports the effective proxy UDP setting (default true).
func (c *Config) UDPEnabled() bool { return c.Proxy.UDP == nil || *c.Proxy.UDP }

// applyDefaults fills zero-valued fields so a sparse YAML still yields a
// coherent config.
func (c *Config) applyDefaults() {
	d := Default()
	if c.Mode == "" {
		c.Mode = d.Mode
	}
	// Single capture mode: drop the deprecated coexistence field so it is not
	// re-emitted (any legacy value is ignored).
	c.Coexistence = ""
	if c.Proxy.Port == 0 {
		c.Proxy.Port = d.Proxy.Port
	}
	if c.DNS.FakeIPv4 == "" {
		c.DNS.FakeIPv4 = d.DNS.FakeIPv4
	}
	// IPv4-only datapath: drop the deprecated fake-ip v6 range so it is not
	// re-emitted (any legacy value is ignored).
	c.DNS.FakeIPv6 = ""
	if c.Control.ClashAPI == "" {
		c.Control.ClashAPI = d.Control.ClashAPI
	}
	if c.Update.Channel == "" {
		c.Update.Channel = d.Update.Channel
	}
	if c.Update.Mode == "" {
		c.Update.Mode = d.Update.Mode
	}
	if c.Update.CheckInterval == "" {
		c.Update.CheckInterval = d.Update.CheckInterval
	}
	if c.ConfigSource.Interval == "" {
		c.ConfigSource.Interval = d.ConfigSource.Interval
	}
}

// Validate checks the config for coherence and returns the first problem found.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeAllowlist, ModeBlocklist:
	default:
		return fmt.Errorf("mode: must be %q or %q, got %q", ModeAllowlist, ModeBlocklist, c.Mode)
	}
	if strings.TrimSpace(c.Proxy.Address) == "" {
		return fmt.Errorf("proxy.address: required")
	}
	if c.Proxy.Port < 1 || c.Proxy.Port > 65535 {
		return fmt.Errorf("proxy.port: must be 1..65535, got %d", c.Proxy.Port)
	}
	if (c.Proxy.Username == "") != (c.Proxy.Password == "") {
		return fmt.Errorf("proxy: username and password must be set together")
	}
	for _, sn := range c.DirectSubnets {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(sn)); err != nil {
			return fmt.Errorf("direct_subnets: invalid CIDR %q: %w", sn, err)
		}
	}
	if _, _, err := net.ParseCIDR(c.DNS.FakeIPv4); err != nil {
		return fmt.Errorf("dns.fakeip_v4: invalid CIDR %q: %w", c.DNS.FakeIPv4, err)
	}
	if host, _, err := net.SplitHostPort(c.Control.ClashAPI); err != nil {
		return fmt.Errorf("control.clash_api: must be host:port, got %q: %w", c.Control.ClashAPI, err)
	} else if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("control.clash_api: must listen on loopback, got %q", host)
	}
	if err := c.validateUpdate(); err != nil {
		return err
	}
	if _, err := time.ParseDuration(c.ConfigSource.Interval); err != nil {
		return fmt.Errorf("config_source.interval: invalid duration %q: %w", c.ConfigSource.Interval, err)
	}
	if u := strings.TrimSpace(c.ConfigSource.URL); u != "" {
		pu, err := url.Parse(u)
		if err != nil || pu.Host == "" || (pu.Scheme != "http" && pu.Scheme != "https") {
			return fmt.Errorf("config_source.url: must be an http(s) URL, got %q", u)
		}
	}
	if pk := strings.TrimSpace(c.ConfigSource.PubKey); pk != "" {
		if raw, err := base64.StdEncoding.DecodeString(pk); err != nil || len(raw) != 32 {
			return fmt.Errorf("config_source.pubkey: must be a base64 32-byte Ed25519 public key")
		}
	}
	if m := strings.TrimSpace(c.ConfigSource.Merge); m != "" && !strings.EqualFold(m, MergeReplace) && !strings.EqualFold(m, MergeOverride) {
		return fmt.Errorf("config_source.merge: must be %q or %q, got %q", MergeReplace, MergeOverride, m)
	}
	return nil
}

func (c *Config) validateUpdate() error {
	switch c.Update.Mode {
	case UpdateOff, UpdateNotify, UpdateAuto:
	default:
		return fmt.Errorf("update.mode: must be %q, %q or %q, got %q", UpdateOff, UpdateNotify, UpdateAuto, c.Update.Mode)
	}
	if _, err := time.ParseDuration(c.Update.CheckInterval); err != nil {
		return fmt.Errorf("update.check_interval: invalid duration %q: %w", c.Update.CheckInterval, err)
	}
	if p := strings.TrimSpace(c.Update.Proxy); p != "" && p != "system" && p != "use-socks" {
		u, err := url.Parse(p)
		if err != nil || u.Host == "" || (u.Scheme != "socks5" && u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("update.proxy: must be '', system, use-socks, or socks5://host:port / http://host:port, got %q", p)
		}
	}
	if e := strings.TrimSpace(c.Update.Endpoint); e != "" {
		u, err := url.Parse(e)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("update.endpoint: must be an http(s) URL, got %q", e)
		}
	}
	return nil
}

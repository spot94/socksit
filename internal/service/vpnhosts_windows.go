//go:build windows

package service

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"

	"socksit/internal/config"
)

// vpnGatewayHosts returns the gateway names of VPN clients installed on this
// machine, so they can be kept off fake-ip.
//
// A VPN client keeps its own control connection OUT of virtual adapters —
// otherwise the tunnel would end up carrying itself — so it dials the gateway on
// the physical interface. Hand it a fake-ip and it sends packets to an address
// that exists only inside our TUN: they leave through the physical gateway and
// die. Cisco AnyConnect then reports "Unable to contact <gateway>" and refuses to
// connect, and stopping SocksIt "fixes" it — so the finger points at us, with
// nothing in our logs to explain it.
//
// This cannot be solved by routing: the client never gives us the packet. The
// only fix is to never hand it a fake address, and the machine already knows
// which names those are — the clients store them in plain sight.
func vpnGatewayHosts() []string {
	seen := map[string]bool{}
	var out []string
	add := func(raw string) {
		if h := hostFromEndpoint(raw); h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, h := range ciscoProfileHosts() {
		add(h)
	}
	for _, h := range fortiTunnelHosts() {
		add(h)
	}
	for _, h := range rasPhonebookHosts() {
		add(h)
	}
	sort.Strings(out)
	return out
}

// hostFromEndpoint reduces whatever a client stored — "host", "host:port",
// "https://host:port/path" — to a bare hostname. Anything that is not a name is
// dropped: an IP literal never gets a fake-ip in the first place, and a display
// label ("Work VPN") would only add noise.
func hostFromEndpoint(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s = strings.TrimSuffix(strings.SplitN(s, "/", 2)[0], ".")
	if i := strings.LastIndex(s, ":"); i > 0 {
		s = s[:i]
	}
	s = strings.ToLower(strings.Trim(s, "[] "))
	if !hostLike.MatchString(s) {
		return ""
	}
	return s
}

// hostLike matches a dotted name and nothing else: no spaces (a display label),
// and not an all-numeric last label (an IPv4 literal).
var hostLike = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$`)

// ciscoHostTag pulls gateway names out of an AnyConnect / Secure Client profile.
// HostAddress is the gateway; HostName is a display label that admins routinely
// set to the gateway too, so both are read and filtered by shape.
var ciscoHostTag = regexp.MustCompile(`(?i)<Host(?:Address|Name)>([^<]+)</Host(?:Address|Name)>`)

func ciscoProfileHosts() []string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return nil
	}
	return ciscoProfileHostsIn([]string{
		filepath.Join(programData, `Cisco\Cisco AnyConnect Secure Mobility Client\Profile`),
		filepath.Join(programData, `Cisco\Cisco Secure Client\VPN\Profile`),
	})
}

func ciscoProfileHostsIn(dirs []string) []string {
	var out []string
	for _, dir := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.xml"))
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, m := range ciscoHostTag.FindAllStringSubmatch(string(b), -1) {
				out = append(out, m[1])
			}
		}
	}
	return out
}

// fortiTunnelHosts reads FortiClient's SSL-VPN tunnels, where each stores its
// gateway as "host:port" (occasionally a comma-separated list of them).
func fortiTunnelHosts() []string {
	var out []string
	for _, root := range []string{
		`SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels`,
		`SOFTWARE\WOW6432Node\Fortinet\FortiClient\Sslvpn\Tunnels`,
	} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, root, registry.READ)
		if err != nil {
			continue
		}
		names, _ := k.ReadSubKeyNames(-1)
		for _, n := range names {
			sub, err := registry.OpenKey(registry.LOCAL_MACHINE, root+`\`+n, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			if server, _, err := sub.GetStringValue("Server"); err == nil {
				out = append(out, strings.Split(server, ";")...)
			}
			sub.Close()
		}
		k.Close()
	}
	var split []string
	for _, s := range out {
		split = append(split, strings.Split(s, ",")...)
	}
	return split
}

// rasPhonebookHosts reads the all-users RAS phonebook, which holds Windows' own
// VPN connections (and the entries some clients register there). The per-user
// phonebook is not read: the service runs as LocalSystem and would only see its
// own profile.
func rasPhonebookHosts() []string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return nil
	}
	return rasPhonebookHostsFrom(filepath.Join(programData, `Microsoft\Network\Connections\Pbk\rasphone.pbk`))
}

func rasPhonebookHostsFrom(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "PhoneNumber="); ok {
			out = append(out, v)
		}
	}
	return out
}

// applyVPNGatewayExemptions keeps the machine's other tunnels working. It runs on
// every config build (a VPN client may be installed or reconfigured while the
// service runs) and logs the list once per change, so the exemption is visible
// rather than magic.
func (r *Runtime) applyVPNGatewayExemptions(cfg *config.Config) {
	hosts := vpnGatewayHosts()
	cfg.ExtraDirectDomains = hosts
	if len(hosts) == 0 {
		return
	}
	joined := strings.Join(hosts, ", ")
	if prev, _ := r.vpnHosts.Load().(string); prev == joined {
		return
	}
	r.vpnHosts.Store(joined)
	r.logf("INFO", "dns: keeping %d VPN gateway name(s) off fake-ip so their client can reach them: %s", len(hosts), joined)
}

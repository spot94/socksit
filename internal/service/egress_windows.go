//go:build windows

package service

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"socksit/internal/config"
	"socksit/internal/engine"
	"socksit/internal/netmon"
	"socksit/internal/singbox"
)

// The SOCKS outbound is pinned to a named adapter (see resolveProxyEgress), which
// is what makes a proxy behind a split-tunnel VPN reachable at all. The cost is
// that the pin also disables sing-box's auto_detect_interface for that one
// outbound — the one every proxied connection uses. So when the adapter that
// reaches the proxy changes while the service runs (VPN up or down, Wi-Fi to
// Ethernet, dock, adapter reset), proxied dials keep leaving through an adapter
// that no longer gets there: zero bytes in both directions, connections piling up
// as the app retries, while direct traffic (no pin) is unaffected and every
// built-in check stays green, because they all dial from the service process
// WITHOUT the pin. Only restarting the service recovered it.
//
// Two ways of detecting this were measured on a live machine and rejected:
//
//   - Re-asking the routing table. resolveProxyEgress is right only because it
//     runs while the engine is down. With the tunnel up, "which adapter reaches
//     the proxy" answers with the tunnel itself — the proxy dial escapes it
//     precisely because bind_interface overrides the route.
//   - Dialling the proxy without binding, as a control. That dial goes into the
//     tunnel, and the tun stack completes the local handshake before anything
//     upstream is attempted, so it succeeds even for an address that leads
//     nowhere. It cannot tell a broken pin from a dead proxy.
//
// So every dial here is bound to a real adapter, and the question is which
// adapters can reach the proxy at all: the pinned one (fine), some other one
// (the pin is stale), or none (the proxy is down and this is not our problem).
//
// This is deliberately not "restart the engine on network changes": that was
// tried and reverted (U6) because the engine edits routes itself and the restarts
// fed on each other. A route edit does not stop the pinned adapter from reaching
// the proxy, so it produces no verdict here.
const (
	// Quiet window before a network change is acted on. A single transition
	// raises a burst of interface/address/route callbacks.
	egressDebounce = 3 * time.Second
	// Backstop poll, for a change notification that never arrived. Kept long:
	// each probe is a real TCP connection to the proxy.
	egressCheckInterval = 5 * time.Minute
	// Until the first verdict exists there is nothing for the panel or `doctor`
	// to report, and a freshly started engine is exactly when someone is looking.
	// Poll faster until one does.
	egressFirstInterval = 15 * time.Second
	// Per-dial budget. A wrong adapter usually fails at once with "unreachable
	// network"; the timeout is for the case where it black-holes instead.
	egressProbeTimeout = 3 * time.Second
)

// egressHealth is what the probe concluded. The values travel to the panel and
// to `socksit doctor` through the status payload.
type egressHealth string

const (
	egressUnknown   egressHealth = ""           // nothing pinned, or nothing to judge yet
	egressOK        egressHealth = "ok"         // the pinned adapter still reaches the proxy
	egressStale     egressHealth = "stale"      // it does not, but another adapter does
	egressProxyDown egressHealth = "proxy-down" // no adapter does: not the pin's fault
)

// egressPin records what the running engine config binds the SOCKS dial to, so a
// later check knows what to test without re-reading the config.
type egressPin struct {
	iface string // adapter the SOCKS dial is bound to; "" = not pinned by us
	host  string // proxy address the pin was resolved for
	port  int
}

func (p egressPin) key() string { return p.iface + "|" + p.host + "|" + strconv.Itoa(p.port) }

func (p egressPin) target() string { return net.JoinHostPort(p.host, strconv.Itoa(p.port)) }

// newEgressPin captures the pin from a config that is about to be generated.
//
// A user-set proxy.interface yields an empty pin on purpose: it is a deliberate
// override, and silently re-pinning it elsewhere on a network change would undo
// the operator's decision without saying so. A proxy named by domain yields an
// empty pin too — resolveProxyEgress does not pin those, so auto_detect_interface
// remains in charge and there is nothing here to go stale.
func newEgressPin(cfg *config.Config, userPinned bool) egressPin {
	host := strings.TrimSpace(cfg.Proxy.Address)
	if userPinned || net.ParseIP(host) == nil {
		return egressPin{}
	}
	return egressPin{iface: strings.TrimSpace(cfg.Proxy.Interface), host: host, port: cfg.Proxy.Port}
}

// judgeEgress is the decision, separated from the dialling so each outcome can be
// tested without a network. alternatives are the other adapters to try, in order;
// dial reports whether the proxy answers when the source is bound to one.
//
// Returns the verdict and the adapter that does reach the proxy (empty if none).
func judgeEgress(p egressPin, alternatives []string, dial func(iface string) error) (egressHealth, string) {
	if p.iface == "" || p.host == "" {
		return egressUnknown, ""
	}
	if dial(p.iface) == nil {
		return egressOK, p.iface
	}
	for _, alt := range alternatives {
		if dial(alt) == nil {
			return egressStale, alt
		}
	}
	// Nobody can reach it. Restarting the engine would not bring the proxy back,
	// and blaming the pin here would turn every proxy outage into a restart.
	return egressProxyDown, ""
}

// candidateAdapters lists the adapters worth trying besides the pinned one:
// up, not loopback, holding a usable IPv4 — and never our own tunnel, which
// answers locally and would vouch for anything.
func candidateAdapters(pinned string) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if strings.EqualFold(ifc.Name, pinned) || strings.EqualFold(ifc.Name, singbox.AdapterName) {
			continue
		}
		if _, err := firstIPv4(ifc.Name); err != nil {
			continue
		}
		out = append(out, ifc.Name)
	}
	return out
}

// firstIPv4 returns an address to dial from for the named adapter. A missing
// adapter or one without an IPv4 address is itself a stale pin: that is what a
// removed dock or a dropped VPN looks like.
func firstIPv4(name string) (net.IP, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if v4 := ipn.IP.To4(); v4 != nil && !v4.IsLinkLocalUnicast() {
				return v4, nil
			}
		}
	}
	return nil, errors.New("adapter has no usable IPv4 address")
}

// dialFrom opens and drops a TCP connection to target with the source bound to
// the named adapter.
//
// Binding the source address is not byte-for-byte what sing-box's bind_interface
// does, but it fails in the same situations: an adapter that is gone, has lost
// its address, or no longer has a path to the proxy.
func dialFrom(iface, target string) error {
	src, err := firstIPv4(iface)
	if err != nil {
		return err
	}
	d := net.Dialer{Timeout: egressProbeTimeout, LocalAddr: &net.TCPAddr{IP: src}}
	c, err := d.Dial("tcp", target)
	if err != nil {
		return err
	}
	return c.Close()
}

// probeEgress reports whether the pin still holds, and which adapter does reach
// the proxy. The healthy case costs one TCP connection; the rest are only tried
// once the pinned adapter has already failed.
func probeEgress(p egressPin) (egressHealth, string) {
	if p.iface == "" || p.host == "" {
		return egressUnknown, ""
	}
	return judgeEgress(p, candidateAdapters(p.iface), func(iface string) error {
		return dialFrom(iface, p.target())
	})
}

// superviseProxyEgress keeps the pinned adapter honest: it watches for the state
// where proxied apps are dead while every other check still passes.
func (r *Runtime) superviseProxyEgress(ctx context.Context) {
	changed := make(chan struct{}, 1)
	mon, err := netmon.Start(egressDebounce, func() {
		select {
		case changed <- struct{}{}:
		default: // a check is already pending
		}
	})
	if err != nil {
		r.logf("WARN", "network change notifications unavailable (%v) — the proxy egress is only re-checked every %s", err, egressCheckInterval)
	} else {
		defer mon.Stop()
	}

	// The pin a restart was already spent on. If it comes back unchanged and
	// still broken, restarting again cannot help — say it once and stop.
	var actedOn string
	for {
		wait := egressCheckInterval
		if h, _ := r.egressHealth.Load().(egressHealth); h == egressUnknown {
			wait = egressFirstInterval
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-changed:
			t.Stop()
		case <-t.C:
		}
		if k := r.checkProxyEgress(actedOn, r.engineSettled(), probeEgress); k != "" {
			actedOn = k
		}
	}
}

// probeFunc is the shape of probeEgress, taken as a parameter so the decision
// path can be tested without a network: staging a genuinely stale pin needs a
// second route to the proxy, which a normal machine does not have.
type probeFunc func(egressPin) (egressHealth, string)

// engineSettled reports whether the engine is up and past its startup. While it
// starts or restarts the routing table is half-built, and a failed dial then says
// nothing about the pin.
func (r *Runtime) engineSettled() bool {
	sup := r.sup.Load()
	return sup != nil && sup.State() == engine.StateRunning
}

// checkProxyEgress runs one probe, publishes the verdict for diagnostics and
// restarts the engine when the pin is the thing that is broken. It returns the
// pin key it acted on, or "" if it did not act.
func (r *Runtime) checkProxyEgress(actedOn string, settled bool, probe probeFunc) string {
	if !r.enabled.Load() || !settled {
		r.egressHealth.Store(egressUnknown)
		return ""
	}
	p, _ := r.egress.Load().(egressPin)
	h, via := probe(p)
	r.egressHealth.Store(h)
	r.egressVia.Store(via)
	if h != egressStale {
		return ""
	}
	if p.key() == actedOn {
		return "" // already restarted for this exact pin; it did not take
	}
	r.logf("WARN", "the proxy %s cannot be reached from %q, which the SOCKS dial is bound to, but answers from %q — the adapter changed under the running engine; restarting it to re-pin (proxied apps get no reply until then)",
		p.target(), p.iface, via)
	r.signalRestart()
	return p.key()
}

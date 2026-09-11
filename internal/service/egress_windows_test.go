//go:build windows

package service

import (
	"errors"
	"testing"

	"socksit/internal/config"
)

// The verdict table is the whole safety argument for restarting the engine on a
// network change — something that was tried before and reverted for churn. Only
// one of these outcomes may lead to a restart.
func TestJudgeEgress(t *testing.T) {
	pin := egressPin{iface: "Ethernet", host: "10.77.10.69", port: 1080}
	boom := errors.New("unreachable network")

	// works names the adapters the proxy answers from; everything else fails.
	dialer := func(works ...string) (func(string) error, *[]string) {
		var tried []string
		return func(iface string) error {
			tried = append(tried, iface)
			for _, w := range works {
				if w == iface {
					return nil
				}
			}
			return boom
		}, &tried
	}

	t.Run("the pinned adapter still reaches the proxy", func(t *testing.T) {
		dial, tried := dialer("Ethernet")
		h, via := judgeEgress(pin, []string{"Wi-Fi"}, dial)
		if h != egressOK || via != "Ethernet" {
			t.Fatalf("got %q via %q", h, via)
		}
		// A healthy pin must not go poking at the other adapters.
		if len(*tried) != 1 {
			t.Errorf("dialled %v, want only the pinned adapter", *tried)
		}
	})

	// The reported failure: apps dead, every check that dials without the pin
	// green. This is the only case worth a restart.
	t.Run("another adapter reaches it: the pin is stale", func(t *testing.T) {
		dial, _ := dialer("Wi-Fi")
		h, via := judgeEgress(pin, []string{"Ethernet 2", "Wi-Fi"}, dial)
		if h != egressStale || via != "Wi-Fi" {
			t.Fatalf("got %q via %q", h, via)
		}
	})

	// Restarting would not bring the proxy back and the probe would repeat every
	// cycle, so blame has to land in the right place.
	t.Run("no adapter reaches it: the proxy is down, not the pin", func(t *testing.T) {
		dial, _ := dialer()
		h, via := judgeEgress(pin, []string{"Ethernet 2", "Wi-Fi"}, dial)
		if h != egressProxyDown || via != "" {
			t.Fatalf("got %q via %q", h, via)
		}
	})

	t.Run("nothing pinned: no verdict and no dialling", func(t *testing.T) {
		dial, tried := dialer("Ethernet")
		for _, p := range []egressPin{{}, {iface: "Ethernet"}, {host: "10.77.10.69", port: 1080}} {
			if h, _ := judgeEgress(p, []string{"Wi-Fi"}, dial); h != egressUnknown {
				t.Errorf("judgeEgress(%+v) = %q, want %q", p, h, egressUnknown)
			}
		}
		if len(*tried) != 0 {
			t.Errorf("dialled %v with nothing pinned", *tried)
		}
	})
}

// Our own tunnel accepts the connection locally before anything upstream is
// tried, so it would vouch for an address that leads nowhere. It must never be
// one of the adapters a verdict rests on.
func TestCandidateAdaptersExcludeTheTunnel(t *testing.T) {
	for _, name := range candidateAdapters("Ethernet") {
		if name == "socksit" {
			t.Fatal("the tunnel adapter must not be a candidate")
		}
		if name == "Ethernet" {
			t.Fatal("the pinned adapter must not be listed again")
		}
	}
}

func TestNewEgressPin(t *testing.T) {
	base := func() *config.Config {
		c := &config.Config{}
		c.Proxy.Address = "10.77.10.69"
		c.Proxy.Port = 1080
		c.Proxy.Interface = "Ethernet"
		return c
	}

	t.Run("auto-resolved pin is recorded", func(t *testing.T) {
		p := newEgressPin(base(), false)
		if p.iface != "Ethernet" || p.host != "10.77.10.69" || p.port != 1080 {
			t.Fatalf("got %+v", p)
		}
		if p.target() != "10.77.10.69:1080" {
			t.Errorf("target() = %q", p.target())
		}
	})

	// An operator who set proxy.interface by hand meant it. Re-pinning that on a
	// network change would quietly undo the override.
	t.Run("a hand-set interface is never re-pinned", func(t *testing.T) {
		if p := newEgressPin(base(), true); p.iface != "" {
			t.Fatalf("expected an empty pin for a user override, got %+v", p)
		}
	})

	// resolveProxyEgress does not pin a proxy named by domain, so nothing there
	// can go stale.
	t.Run("a domain proxy is not pinned", func(t *testing.T) {
		c := base()
		c.Proxy.Address = "proxy.corp.example"
		c.Proxy.Interface = ""
		if p := newEgressPin(c, false); p.iface != "" || p.host != "" {
			t.Fatalf("expected an empty pin for a domain proxy, got %+v", p)
		}
	})
}

// A pin whose adapter is gone is stale by definition: that is what a removed
// dock or a dropped VPN adapter looks like.
func TestFirstIPv4RejectsAMissingAdapter(t *testing.T) {
	if _, err := firstIPv4("no such adapter, surely"); err == nil {
		t.Fatal("expected an error for an adapter that does not exist")
	}
}

// The wiring between a stale verdict and the restart is the one link a live test
// could not reach: staging a genuinely stale pin needs a second route to the
// proxy, and a machine with one uplink has none. So it is covered here, with the
// probe injected.
func TestCheckProxyEgressActsOnlyOnAStalePin(t *testing.T) {
	pin := egressPin{iface: "Ethernet", host: "10.77.10.69", port: 1080}

	newRuntime := func() *Runtime {
		r := &Runtime{restartCh: make(chan struct{}, 1)}
		r.enabled.Store(true)
		r.egress.Store(pin)
		return r
	}
	restarted := func(r *Runtime) bool {
		select {
		case <-r.restartCh:
			return true
		default:
			return false
		}
	}
	probing := func(h egressHealth, via string) probeFunc {
		return func(egressPin) (egressHealth, string) { return h, via }
	}

	t.Run("stale: restarts and reports the pin it acted on", func(t *testing.T) {
		r := newRuntime()
		got := r.checkProxyEgress("", true, probing(egressStale, "Wi-Fi"))
		if got != pin.key() {
			t.Errorf("acted on %q, want %q", got, pin.key())
		}
		if !restarted(r) {
			t.Error("no restart signalled for a stale pin")
		}
		if h, _ := r.egressHealth.Load().(egressHealth); h != egressStale {
			t.Errorf("published %q, want %q", h, egressStale)
		}
		if via, _ := r.egressVia.Load().(string); via != "Wi-Fi" {
			t.Errorf("published via %q, want Wi-Fi", via)
		}
	})

	// A restart that did not take must not be repeated: the pin came back the
	// same, so the next one would not help either.
	t.Run("stale twice on the same pin: only one restart", func(t *testing.T) {
		r := newRuntime()
		if got := r.checkProxyEgress(pin.key(), true, probing(egressStale, "Wi-Fi")); got != "" {
			t.Errorf("acted again on %q", got)
		}
		if restarted(r) {
			t.Error("restarted twice for the same pin")
		}
		// The verdict is still published: diagnostics must keep saying it is broken.
		if h, _ := r.egressHealth.Load().(egressHealth); h != egressStale {
			t.Errorf("published %q, want %q", h, egressStale)
		}
	})

	for _, c := range []struct {
		name    string
		health  egressHealth
		settled bool
		enabled bool
	}{
		{"healthy pin", egressOK, true, true},
		{"proxy down: not the pin's fault", egressProxyDown, true, true},
		{"engine still starting", egressStale, false, true},
		{"proxying paused", egressStale, true, false},
	} {
		t.Run("no restart: "+c.name, func(t *testing.T) {
			r := newRuntime()
			r.enabled.Store(c.enabled)
			if got := r.checkProxyEgress("", c.settled, probing(c.health, "Wi-Fi")); got != "" {
				t.Errorf("acted on %q", got)
			}
			if restarted(r) {
				t.Error("restarted when it should not have")
			}
		})
	}
}

//go:build windows

package service

import (
	"testing"

	"socksit/internal/config"
)

// TestResolveProxyEgress covers the deterministic (no-network) branches: an
// explicit proxy.interface is preserved, and a domain proxy is not auto-resolved.
// The IP-resolution path dials the network and is exercised on a real host.
func TestResolveProxyEgress(t *testing.T) {
	r := &Runtime{} // r.log nil → logf is a no-op

	pinned := config.Default()
	pinned.Proxy.Address = "10.77.10.69"
	pinned.Proxy.Port = 1080
	pinned.Proxy.Interface = "Ethernet 9"
	r.resolveProxyEgress(pinned)
	if pinned.Proxy.Interface != "Ethernet 9" {
		t.Errorf("explicit interface must be preserved, got %q", pinned.Proxy.Interface)
	}

	domain := config.Default()
	domain.Proxy.Address = "proxy.corp.local"
	domain.Proxy.Port = 1080
	r.resolveProxyEgress(domain)
	if domain.Proxy.Interface != "" {
		t.Errorf("domain proxy must not be auto-resolved, got %q", domain.Proxy.Interface)
	}
}

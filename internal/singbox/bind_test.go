package singbox

import (
	"strings"
	"testing"

	"socksit/internal/config"
)

// TestProxyBindInterface verifies proxy.interface flows into the SOCKS outbound
// as bind_interface (the fix for a proxy reachable only via a split-tunnel VPN),
// and is absent when unset.
func TestProxyBindInterface(t *testing.T) {
	c := config.Default()
	c.Proxy.Address = "10.77.10.69"
	c.Proxy.Port = 1080
	c.Apps = []string{"discord.exe"}

	js, err := GenerateJSON(c)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if strings.Contains(string(js), "bind_interface") {
		t.Errorf("bind_interface must be absent when proxy.interface is empty:\n%s", js)
	}

	c.Proxy.Interface = "Ethernet 2"
	js, err = GenerateJSON(c)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.Contains(string(js), `"bind_interface": "Ethernet 2"`) {
		t.Errorf("expected bind_interface on the proxy outbound:\n%s", js)
	}
}

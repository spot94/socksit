package config

import "testing"

// A bootstrap preset carries nothing but where to fetch the real settings from.
// Requiring proxy.address in it forced every installer to duplicate values it
// does not own — and a duplicate is a second source of truth that drifts.
func TestManagedConfigNeedsNoProxyAddress(t *testing.T) {
	managed := []byte(`
config_source:
  url: https://configs.example.com/configs/ai-team/socksit.yaml
  signed: true
  pubkey: mo3qKmrGGUZJi8EBXBctBQIb8ALIdahyD1BCWxoCWIE=
  merge: override
kill_switch: true
`)
	c, err := Parse(managed)
	if err != nil {
		t.Fatalf("a managed bootstrap preset must validate: %v", err)
	}
	if !c.ConfigManaged() {
		t.Error("expected managed mode")
	}

	// Without a feed there is nothing to wait for, so the requirement stands:
	// an installer that forgets the proxy would otherwise produce a service that
	// silently never proxies anything.
	unmanaged := []byte("kill_switch: true\n")
	if _, err := Parse(unmanaged); err == nil {
		t.Error("an unmanaged config with no proxy.address must still be rejected")
	}

	// Everything else stays checked: managed mode is not a way past validation.
	bad := []byte(`
config_source:
  url: https://configs.example.com/socksit.yaml
  merge: sideways
`)
	if _, err := Parse(bad); err == nil {
		t.Error("a managed config with an invalid merge mode must be rejected")
	}
}

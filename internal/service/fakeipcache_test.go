//go:build windows

package service

import (
	"os"
	"path/filepath"
	"testing"

	"socksit/internal/config"
	"socksit/internal/singbox"
)

// writeGenerated writes a generated engine config carrying the given fake-ip
// range, standing in for the previous run's config.json.
func writeGenerated(t *testing.T, dir, fakeIP string) {
	t.Helper()
	c := config.Default()
	c.Proxy.Address = "10.0.0.1"
	c.DNS.FakeIPv4 = fakeIP
	c.BypassCIDRs = []string{} // keep the range out of the bypass list for this fixture
	js, err := singbox.GenerateJSON(c)
	if err != nil {
		t.Fatalf("generate fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), js, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestFakeIPCacheInvalidatedOnRangeChange guards the interaction between the two
// fixes: the persisted fake-ip table must not outlive a change of the range it
// was built from, or apps keep being handed addresses nothing routes.
func TestFakeIPCacheInvalidatedOnRangeChange(t *testing.T) {
	dir := t.TempDir()
	r := &Runtime{DataDir: dir} // log nil -> logf is a no-op
	cachePath := filepath.Join(dir, "cache.db")
	mkCache := func() {
		if err := os.WriteFile(cachePath, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Range changed (Class E -> the restored default): the cache must go.
	writeGenerated(t, dir, "240.0.0.0/15")
	mkCache()
	cfg := config.Default()
	cfg.DNS.FakeIPv4 = "198.18.0.0/15"
	cfg.CachePath = cachePath
	r.invalidateFakeIPCache(cfg)
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Error("cache must be cleared when the fake-ip range changes")
	}

	// Range unchanged: the cache is what makes restarts survivable — keep it.
	writeGenerated(t, dir, "198.18.0.0/15")
	mkCache()
	r.invalidateFakeIPCache(cfg)
	if _, err := os.Stat(cachePath); err != nil {
		t.Errorf("cache must be kept when the range is unchanged: %v", err)
	}

	// No previous generated config (first run): nothing to compare, keep it.
	os.Remove(filepath.Join(dir, "config.json"))
	r.invalidateFakeIPCache(cfg)
	if _, err := os.Stat(cachePath); err != nil {
		t.Errorf("cache must be kept when there is no previous config: %v", err)
	}
}

func TestPreviousFakeIPRange(t *testing.T) {
	dir := t.TempDir()
	r := &Runtime{DataDir: dir}
	if got := r.previousFakeIPRange(); got != "" {
		t.Errorf("no config.json should report %q, got %q", "", got)
	}
	writeGenerated(t, dir, "240.0.0.0/15")
	if got := r.previousFakeIPRange(); got != "240.0.0.0/15" {
		t.Errorf("previousFakeIPRange = %q, want 240.0.0.0/15", got)
	}
}

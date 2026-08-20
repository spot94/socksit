package singbox

import (
	"strings"
	"testing"

	"socksit/internal/config"
)

// TestCacheFilePersistsFakeIP guards the fix for "the app vanishes from
// Statistics until it is restarted": without a persisted fake-ip table every
// engine restart invalidates addresses apps have already cached.
func TestCacheFilePersistsFakeIP(t *testing.T) {
	c := config.Default()
	c.Proxy.Address = "10.0.0.1"
	c.Apps = []string{"claude.exe"}
	c.CachePath = `C:\ProgramData\SocksIt\cache.db`

	sb, err := Generate(c)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	cf := sb.Experimental.CacheFile
	if cf == nil {
		t.Fatal("expected experimental.cache_file to be emitted")
	}
	if !cf.Enabled || !cf.StoreFakeIP {
		t.Errorf("cache_file must be enabled with store_fakeip, got %+v", cf)
	}
	if cf.Path != c.CachePath {
		t.Errorf("cache_file path = %q, want %q", cf.Path, c.CachePath)
	}

	js, err := Marshal(sb)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `"store_fakeip": true`) {
		t.Errorf("store_fakeip missing from the generated JSON:\n%s", js)
	}

	// The engine itself must accept the shape we emit (cache_file + store_fakeip).
	checkWithEngine(t, c)

	// No path (e.g. `socksit config gen`) → the key is omitted entirely.
	c.CachePath = ""
	sb2, err := Generate(c)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if sb2.Experimental.CacheFile != nil {
		t.Error("cache_file must be omitted when no path is configured")
	}
}

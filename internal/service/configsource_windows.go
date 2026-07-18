//go:build windows

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"socksit/internal/config"
	"socksit/internal/updates"
)

// configFetchResult is the JSON-friendly status of the managed-config feed.
type configFetchResult struct {
	Managed  bool   `json:"managed"`
	URL      string `json:"url"`
	Signed   bool   `json:"signed"`
	Interval string `json:"interval"`
	Fetched  string `json:"fetched"` // RFC3339 of the last successful fetch, or ""
	Changed  bool   `json:"changed"` // the last fetch changed the local config
	Error    string `json:"error"`
}

// ConfigStatus returns the last cached managed-config status.
func (r *Runtime) ConfigStatus() (any, error) {
	if p := r.lastConfig.Load(); p != nil {
		return *p, nil
	}
	cfg := r.lenientConfig()
	return configFetchResult{Managed: cfg.ConfigManaged(), URL: cfg.ConfigSource.URL, Signed: cfg.ConfigSigned(), Interval: cfg.ConfigSource.Interval}, nil
}

// ConfigFetch fetches the managed config now and returns the result (errors are
// folded into Result.Error so the UI always gets a payload).
func (r *Runtime) ConfigFetch() (any, error) {
	res, _ := r.fetchConfig(context.Background())
	return res, nil
}

// superviseConfigSource fetches the managed config shortly after start and then
// on the configured interval, applying it (via the hot-reload watcher) when it
// changes. Runs until ctx is cancelled.
func (r *Runtime) superviseConfigSource(ctx context.Context) {
	timer := time.NewTimer(10 * time.Second) // fetch soon after start
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		next := 5 * time.Minute // re-check whether managed mode was enabled
		cfg := r.lenientConfig()
		if cfg.ConfigManaged() {
			if _, err := r.fetchConfig(ctx); err != nil {
				fmt.Fprintf(r.log, "config fetch failed: %v\n", err)
			}
			next = cfg.ConfigEvery()
		}
		timer.Reset(next)
	}
}

// fetchConfig pulls the remote config, verifies it (signature when required),
// validates it, and writes socksit.yaml when it differs — preserving the local
// config_source so managed mode can't disable or lock itself.
func (r *Runtime) fetchConfig(ctx context.Context) (configFetchResult, error) {
	cfg := r.lenientConfig()
	res := configFetchResult{Managed: cfg.ConfigManaged(), URL: cfg.ConfigSource.URL, Signed: cfg.ConfigSigned(), Interval: cfg.ConfigSource.Interval}
	if !cfg.ConfigManaged() {
		r.lastConfig.Store(&res)
		return res, nil
	}
	client, err := r.buildUpdateClient(cfg)
	if err != nil {
		res.Error = err.Error()
		r.lastConfig.Store(&res)
		return res, err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	body, err := httpGetBytes(cctx, client, cfg.ConfigSource.URL, 1<<20)
	if err != nil {
		res.Error = err.Error()
		r.lastConfig.Store(&res)
		return res, err
	}
	if cfg.ConfigSigned() {
		if strings.TrimSpace(cfg.ConfigSource.PubKey) == "" {
			err := errors.New("config_source.signed is on but no trusted key (pubkey) is set")
			res.Error = err.Error()
			r.lastConfig.Store(&res)
			return res, err
		}
		sig, err := httpGetBytes(cctx, client, cfg.ConfigSource.URL+".sig", 64<<10)
		if err != nil {
			res.Error = "signature: " + err.Error()
			r.lastConfig.Store(&res)
			return res, err
		}
		if err := updates.VerifyWithKeyB64(body, string(sig), cfg.ConfigSource.PubKey); err != nil {
			res.Error = "signature: " + err.Error()
			r.lastConfig.Store(&res)
			return res, err
		}
	}
	var newCfg *config.Config
	if cfg.MergeMode() == config.MergeOverride {
		newCfg, err = mergeManagedConfig(cfg, body)
	} else {
		if newCfg, err = config.Parse(body); err == nil {
			newCfg.ConfigSource = cfg.ConfigSource // keep local policy
			newCfg.ManagedApps = nil               // replace mode has no separate managed set
		}
	}
	if err != nil {
		res.Error = "remote config is invalid: " + err.Error()
		r.lastConfig.Store(&res)
		return res, err
	}

	newBytes, err := yaml.Marshal(newCfg)
	if err != nil {
		res.Error = err.Error()
		r.lastConfig.Store(&res)
		return res, err
	}
	if curBytes, _ := yaml.Marshal(cfg); !bytes.Equal(newBytes, curBytes) {
		if err := os.WriteFile(r.configPath(), newBytes, 0o600); err != nil {
			res.Error = err.Error()
			r.lastConfig.Store(&res)
			return res, err
		}
		res.Changed = true
		fmt.Fprintf(r.log, "config: applied managed config from %s\n", cfg.ConfigSource.URL)
		r.signalRestart() // in addition to the file watcher
	}
	res.Fetched = time.Now().UTC().Format(time.RFC3339)
	r.lastConfig.Store(&res)
	return res, nil
}

// mergeManagedConfig applies the remote config as an OVERRIDE onto the current
// local config: only the keys the remote actually specifies (recursing into
// nested maps) replace local values; everything the remote omits keeps its local
// value. The app lists are unioned instead of replaced — the user's own apps are
// preserved and the remote's apps are mirrored into managed_apps, which
// EffectiveApps combines at generate time. The local config_source policy is
// preserved so the feed can't reconfigure or lock itself.
func mergeManagedConfig(local *config.Config, remoteBody []byte) (*config.Config, error) {
	var remoteMap map[string]any
	if err := yaml.Unmarshal(remoteBody, &remoteMap); err != nil {
		return nil, err
	}
	if len(remoteMap) == 0 {
		return nil, errors.New("remote config is empty")
	}
	localBytes, err := yaml.Marshal(local)
	if err != nil {
		return nil, err
	}
	var localMap map[string]any
	if err := yaml.Unmarshal(localBytes, &localMap); err != nil {
		return nil, err
	}
	if localMap == nil {
		localMap = map[string]any{}
	}
	merged := deepMerge(localMap, remoteMap)
	// App lists union rather than replace: keep the user's own apps, and mirror the
	// remote's apps into managed_apps (EffectiveApps combines them at generate time).
	merged["apps"] = localMap["apps"]
	if ra, ok := remoteMap["apps"]; ok {
		merged["managed_apps"] = ra
	} else {
		merged["managed_apps"] = localMap["managed_apps"]
	}
	// Preserve the local managed-config policy (URL, key, interval, merge mode).
	merged["config_source"] = localMap["config_source"]

	mergedBytes, err := yaml.Marshal(merged)
	if err != nil {
		return nil, err
	}
	return config.Parse(mergedBytes)
}

// deepMerge returns a copy of base with patch applied: keys present in patch
// override base, recursing into nested maps; keys absent from patch keep their
// base value.
func deepMerge(base, patch map[string]any) map[string]any {
	out := make(map[string]any, len(base))
	for k, v := range base {
		out[k] = v
	}
	for k, pv := range patch {
		if bv, ok := out[k]; ok {
			if bm, ok1 := bv.(map[string]any); ok1 {
				if pm, ok2 := pv.(map[string]any); ok2 {
					out[k] = deepMerge(bm, pm)
					continue
				}
			}
		}
		out[k] = pv
	}
	return out
}

func httpGetBytes(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

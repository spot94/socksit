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
	newCfg, err := config.Parse(body)
	if err != nil {
		res.Error = "remote config is invalid: " + err.Error()
		r.lastConfig.Store(&res)
		return res, err
	}
	newCfg.ConfigSource = cfg.ConfigSource // keep local policy

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

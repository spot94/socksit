//go:build windows

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"socksit/internal/config"
	"socksit/internal/updates"
)

// UpdateStatus returns the last cached check result (never fails).
func (r *Runtime) UpdateStatus() (any, error) {
	if p := r.lastUpdate.Load(); p != nil {
		return *p, nil
	}
	return updates.Result{Current: r.Version}, nil
}

// UpdateCheck runs a check now and returns the result. Errors are folded into
// Result.Error so the UI always gets a payload.
func (r *Runtime) UpdateCheck() (any, error) {
	res, _ := r.runUpdateCheck(context.Background())
	return res, nil
}

// runUpdateCheck loads config, builds an HTTP client per update.proxy, checks the
// signed manifest, and caches the result.
func (r *Runtime) runUpdateCheck(ctx context.Context) (updates.Result, error) {
	cfg := r.lenientConfig()
	client, err := r.buildUpdateClient(cfg)
	if err != nil {
		res := updates.Result{Current: r.Version, Error: err.Error()}
		r.lastUpdate.Store(&res)
		return res, err
	}
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	res, err := updates.Check(cctx, client, cfg.Update.Endpoint, cfg.Update.Channel, r.Version)
	if err != nil {
		res.Error = err.Error()
	}
	r.lastUpdate.Store(&res)
	return res, err
}

// superviseUpdates periodically checks for updates when enabled (notify-only in
// this phase — it never applies anything). Runs until ctx is cancelled.
func (r *Runtime) superviseUpdates(ctx context.Context) {
	timer := time.NewTimer(30 * time.Second) // let startup settle first
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		next := time.Hour // when disabled, re-read config hourly
		cfg := r.lenientConfig()
		if cfg.UpdatesEnabled() {
			if _, err := r.runUpdateCheck(ctx); err != nil {
				r.logf("WARN", "update check failed: %v", err)
			} else if res := r.lastUpdate.Load(); res != nil && res.HasUpdate {
				r.logf("INFO", "update available: %s (current %s)", res.Available, res.Current)
			}
			next = cfg.CheckEvery()
		}
		timer.Reset(next)
	}
}

// lenientConfig reads the config without requiring a fully-valid proxy (so update
// checks work even before the proxy is configured, unless proxy: use-socks).
func (r *Runtime) lenientConfig() *config.Config {
	if b, err := os.ReadFile(r.configPath()); err == nil {
		return config.ParseLenient(b)
	}
	return config.Default()
}

// buildUpdateClient constructs an HTTP client honoring update.proxy, injecting
// the stored SOCKS5 credentials for use-socks.
func (r *Runtime) buildUpdateClient(cfg *config.Config) (*http.Client, error) {
	return r.buildProxyClient(cfg.Update.Proxy, cfg)
}

// buildProxyClient builds an HTTP client for an arbitrary proxy mode (update.proxy
// or config_source.proxy), injecting the stored SOCKS5 credentials for use-socks.
func (r *Runtime) buildProxyClient(mode string, cfg *config.Config) (*http.Client, error) {
	var auth *proxy.Auth
	if u, pass, ok := r.loadCreds(); ok && u != "" {
		auth = &proxy.Auth{User: u, Password: pass}
	}
	return updateHTTPClient(mode, cfg, auth)
}

// updateHTTPClient builds an HTTP client for the given proxy mode. cfg supplies the
// SOCKS address for use-socks. For use-socks with no proxy configured yet it
// connects directly, so a first-run engine download still works.
func updateHTTPClient(mode string, cfg *config.Config, auth *proxy.Auth) (*http.Client, error) {
	tr := &http.Transport{}
	switch p := strings.TrimSpace(mode); {
	case p == "":
		// direct
	case p == "system":
		tr.Proxy = http.ProxyFromEnvironment
	case p == "use-socks":
		if addr := strings.TrimSpace(cfg.Proxy.Address); addr != "" {
			if err := setSocksDialer(tr, net.JoinHostPort(addr, strconv.Itoa(cfg.Proxy.Port)), auth); err != nil {
				return nil, err
			}
		}
	default:
		pu, err := url.Parse(p)
		if err != nil {
			return nil, fmt.Errorf("proxy: %w", err)
		}
		switch pu.Scheme {
		case "http", "https":
			tr.Proxy = http.ProxyURL(pu)
		case "socks5":
			if pu.User != nil {
				pw, _ := pu.User.Password()
				auth = &proxy.Auth{User: pu.User.Username(), Password: pw}
			}
			if err := setSocksDialer(tr, pu.Host, auth); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("proxy: unsupported scheme %q", pu.Scheme)
		}
	}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}, nil
}

// loadStoredCreds reads DPAPI-encrypted SOCKS5 credentials from dataDir (nil if
// none). Used by Install, which has no Runtime, for a use-socks engine download.
func loadStoredCreds(dataDir string) *proxy.Auth {
	blob, err := secretStore().LoadFrom(filepath.Join(dataDir, "creds.dpapi"))
	if err != nil {
		return nil
	}
	var c creds
	if json.Unmarshal([]byte(blob), &c) != nil || c.User == "" {
		return nil
	}
	return &proxy.Auth{User: c.User, Password: c.Pass}
}

func setSocksDialer(tr *http.Transport, addr string, auth *proxy.Auth) error {
	d, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
	if err != nil {
		return err
	}
	if cd, ok := d.(proxy.ContextDialer); ok {
		tr.DialContext = cd.DialContext
	} else {
		tr.DialContext = func(_ context.Context, network, address string) (net.Conn, error) {
			return d.Dial(network, address)
		}
	}
	return nil
}

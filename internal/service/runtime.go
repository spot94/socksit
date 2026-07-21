//go:build windows

// Package service hosts SocksIt as a Windows service and orchestrates the
// runtime: reconcile -> load config -> generate+check config.json -> supervise
// the engine, while serving the IPC control channel and healing on
// network/config changes. See plan U3.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"socksit/internal/audit"
	"socksit/internal/config"
	"socksit/internal/engine"
	"socksit/internal/ipc"
	"socksit/internal/logfile"
	"socksit/internal/netstate"
	"socksit/internal/singbox"
	"socksit/internal/updates"
)

// credentialEntropy salts the DPAPI blob (defense in depth; see KTD7).
const credentialEntropy = "socksit-credentials-v1"

// Log rotation thresholds. socksit.log captures the whole engine output for an
// always-on service, so it is capped tightly; audit.log grows slowly but must
// keep a long trail (SEC-3), so it rotates with generous retention.
const (
	runtimeLogMaxSize = 10 << 20 // 10 MiB per segment (~40 MiB with backups)
	runtimeLogBackups = 3
	auditLogMaxSize   = 5 << 20 // 5 MiB per segment (~55 MiB of audit history)
	auditLogBackups   = 10
)

// Runtime ties the components together. It runs identically under the SCM and
// in interactive/debug mode.
type Runtime struct {
	DataDir    string // %ProgramData%\SocksIt
	EnginePath string // sing-box.exe
	PipeName   string // IPC pipe (production: ipc.DefaultPipeName)
	Actor      string // audit actor (local username)
	Version    string // app version, reported to the update check

	enabled    atomic.Bool
	sup        atomic.Pointer[engine.Supervisor]
	restartCh  chan struct{}
	log        io.Writer
	lastUpdate  atomic.Pointer[updates.Result]
	autoApplied atomic.Value // string: last version auto-applied, so auto mode won't re-attempt the same one
	lastConfig atomic.Pointer[configFetchResult]
}

func (r *Runtime) configPath() string { return filepath.Join(r.DataDir, "socksit.yaml") }
func (r *Runtime) genPath() string    { return filepath.Join(r.DataDir, "config.json") }
func (r *Runtime) credsPath() string  { return filepath.Join(r.DataDir, "creds.dpapi") }

// Run executes the runtime until ctx is cancelled.
func (r *Runtime) Run(ctx context.Context) error {
	if r.log == nil {
		r.log = os.Stdout
	}
	r.enabled.Store(true)
	r.restartCh = make(chan struct{}, 1)

	if err := os.MkdirAll(r.DataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	ensureUserWritable(r.DataDir)
	// Mirror engine + service output to a log file (keeps the console for `run`).
	// safeMulti ignores per-writer errors, so a missing console (GUI-subsystem
	// service) never blocks the file write.
	if rot, err := logfile.NewRotator(filepath.Join(r.DataDir, "socksit.log"), runtimeLogMaxSize, runtimeLogBackups); err == nil {
		r.log = safeMulti{r.log, rot}
		defer rot.Close()
	}
	if r.ensureFirstRunConfig() {
		r.logf("INFO", "first run: created a default config at %s", r.configPath())
	}
	r.logf("INFO", "starting SocksIt %s (config %s, logs %s)", r.Version, r.configPath(), r.DataDir)
	r.logf("INFO", "edit settings via `socksit gui`, the tray icon, or the config file (changes apply automatically)")

	var auditW io.Writer = io.Discard
	if rot, err := logfile.NewRotator(filepath.Join(r.DataDir, "audit.log"), auditLogMaxSize, auditLogBackups); err == nil {
		auditW = rot
		defer rot.Close()
	}
	auditLog := audit.New(auditW)

	if needs, detail, err := netstate.Reconcile(); err == nil && needs {
		r.logf("INFO", "reconcile: %s", detail)
		auditLog.Log("service", "reconciled stale network state", detail)
	}

	// Config hot-reload: editing socksit.yaml (or GUI Save) triggers a reload.
	if err := config.Watch(ctx, r.configPath(), 500*time.Millisecond, r.signalRestart); err != nil {
		r.logf("WARN", "config watch unavailable: %v", err)
	}
	// NOTE: network-change self-heal is handled inside sing-box via
	// auto_detect_interface. We deliberately do NOT restart the engine on route
	// changes here — doing so reacts to sing-box's own auto_route edits and causes
	// restart churn (proxy works for a few seconds, then drops). See U6 revision.

	// IPC control server.
	srv := ipc.NewServer(r, auditLog, r.Actor)
	sddl := ipc.BuildSDDL(consoleUserSID(r.log))
	if err := srv.Listen(r.PipeName, sddl); err != nil {
		return fmt.Errorf("could not create the control pipe %s — this needs the installed service (LocalSystem) or an elevated (Administrator) console: %w", r.PipeName, err)
	}
	go srv.Serve(ctx)
	defer srv.Close()

	// Keep a tray alive in the interactive session for as long as the service
	// runs (tray presence is bound to the service — see traykeeper_windows.go).
	go r.superviseTray(ctx)

	// Periodic update checks (notify-only; see update_windows.go).
	go r.superviseUpdates(ctx)

	// Managed-config feed: fetch on start + on interval (see configsource_windows.go).
	go r.superviseConfigSource(ctx)

	return r.superviseLoop(ctx)
}

// superviseLoop (re)generates the engine config and supervises it, restarting
// on reload/heal signals and honoring the enabled flag.
func (r *Runtime) superviseLoop(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !r.enabled.Load() {
			// Proxying disabled: idle until re-enabled or shutdown.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-r.restartCh:
				continue
			}
		}

		cfg, err := r.effectiveConfig()
		if err != nil {
			r.logf("WARN", "waiting for a valid config at %s — %v (set proxy.address and add apps; changes apply automatically)", r.configPath(), err)
			if !r.waitRestart(ctx) {
				return ctx.Err()
			}
			continue
		}
		r.resolveProxyEgress(cfg) // pin the SOCKS dial to the adapter that reaches the proxy (VPN-safe)
		js, err := singbox.GenerateJSON(cfg)
		if err == nil {
			err = os.WriteFile(r.genPath(), js, 0o600)
		}
		if err == nil {
			err = singbox.Check(r.EnginePath, r.genPath())
		}
		if err != nil {
			r.logf("ERROR", "generate/check failed (keeping previous, holding): %v", err)
			if !r.waitRestart(ctx) {
				return ctx.Err()
			}
			continue
		}

		sup := engine.New(engine.Options{
			EnginePath: r.EnginePath,
			ConfigPath: r.genPath(),
			ReadyAddr:  cfg.Control.ClashAPI,
			Stdout:     r.log,
		})
		r.sup.Store(sup)

		childCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { _ = sup.Run(childCtx); close(done) }()

		select {
		case <-ctx.Done():
			cancel()
			r.awaitEngineStop(done)
			r.sup.Store(nil)
			return ctx.Err()
		case <-r.restartCh:
			cancel()
			r.awaitEngineStop(done)
			r.sup.Store(nil)
			// loop: regenerate with the new config / after the network change
		case <-done:
			// Supervisor gave up (crash-loop). Wait for a restart signal.
			cancel()
			r.sup.Store(nil)
			if !r.waitRestart(ctx) {
				return ctx.Err()
			}
		}
	}
}

// engineStopTimeout bounds how long superviseLoop waits for the engine to stop
// after cancelling it. The supervisor force-kills the child on cancel, so this is
// a backstop: if the engine is somehow unkillable we log and move on instead of
// wedging shutdown/restart forever (the OS reaps it via the job's kill-on-close
// when the service process exits).
const engineStopTimeout = 8 * time.Second

// awaitEngineStop waits for the supervisor goroutine to finish, bounded so a stuck
// child can never block the loop indefinitely.
func (r *Runtime) awaitEngineStop(done <-chan struct{}) {
	select {
	case <-done:
	case <-time.After(engineStopTimeout):
		r.logf("ERROR", "engine did not stop within %s after cancel — continuing without blocking", engineStopTimeout)
	}
}

func (r *Runtime) waitRestart(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-r.restartCh:
		return true
	}
}

func (r *Runtime) signalRestart() {
	select {
	case r.restartCh <- struct{}{}:
	default: // a restart is already pending
	}
}

// effectiveConfig loads the YAML and injects stored credentials (kept out of the
// YAML — only in the DPAPI blob).
func (r *Runtime) effectiveConfig() (*config.Config, error) {
	cfg, err := config.Load(r.configPath())
	if err != nil {
		return nil, err
	}
	// If the config left managed mode (url cleared) but channel remnants remain
	// — e.g. the file was edited directly — normalize it once and persist the
	// creds-free file (before injecting credentials, so they never hit the YAML).
	if cfg.DemoteIfUnmanaged() {
		if b, mErr := yaml.Marshal(cfg); mErr == nil {
			_ = os.WriteFile(r.configPath(), b, 0o600)
		}
	}
	if u, p, ok := r.loadCreds(); ok {
		cfg.Proxy.Username, cfg.Proxy.Password = u, p
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// resolveProxyEgress pins proxy.interface (in memory, for this generation only)
// to the local adapter that actually reaches the SOCKS server. Without it,
// sing-box's auto_detect_interface binds the proxy dial to the physical default
// interface, so a proxy reachable only via a split-tunnel VPN (e.g. Cisco
// AnyConnect) times out. No-op if the user pinned proxy.interface, or the proxy is
// a domain (only IP proxies are auto-resolved). Re-runs on every (re)start, so a
// VPN connected before start/apply is picked up automatically.
func (r *Runtime) resolveProxyEgress(cfg *config.Config) {
	if strings.TrimSpace(cfg.Proxy.Interface) != "" {
		return // explicit user override wins
	}
	if net.ParseIP(strings.TrimSpace(cfg.Proxy.Address)) == nil {
		return // domain proxy: can't route-resolve a name here, leave to auto_detect
	}
	if name := interfaceForDest(cfg.Proxy.Address, cfg.Proxy.Port); name != "" {
		cfg.Proxy.Interface = name
		r.logf("INFO", "proxy %s:%d reached via interface %q — binding the SOCKS dial to it", cfg.Proxy.Address, cfg.Proxy.Port, name)
	}
}

// interfaceForDest returns the name of the local interface the OS would use to
// reach host:port, honouring the routing table (so a more-specific VPN route wins
// over SocksIt's own default-into-TUN). The UDP "connect" sends no packets — it
// only makes the OS choose a source address, which we map back to an interface.
func interfaceForDest(host string, port int) string {
	conn, err := net.Dial("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return ""
	}
	defer conn.Close()
	ua, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || ua.IP == nil || ua.IP.IsUnspecified() {
		return ""
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(ua.IP) {
				return ifc.Name
			}
		}
	}
	return ""
}

type creds struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

func (r *Runtime) loadCreds() (user, pass string, ok bool) {
	blob, err := secretStore().LoadFrom(r.credsPath())
	if err != nil {
		return "", "", false
	}
	var c creds
	if json.Unmarshal([]byte(blob), &c) != nil {
		return "", "", false
	}
	return c.User, c.Pass, true
}

// ensureFirstRunConfig writes a default config if none exists. Returns true if
// it created the file.
func (r *Runtime) ensureFirstRunConfig() bool {
	if _, err := os.Stat(r.configPath()); err == nil {
		return false
	}
	// Write the full built-in default (single source of truth) so the file is
	// complete and correct out of the box — including the update endpoint, which a
	// minimal template used to omit, leaving new users unable to update.
	header := []byte("# SocksIt — set proxy.address and add apps, then save.\n" +
		"# Easiest: run `socksit gui`. Changes apply automatically.\n")
	body, err := yaml.Marshal(config.Default())
	if err != nil {
		return false
	}
	return os.WriteFile(r.configPath(), append(header, body...), 0o600) == nil
}

// ensureUserWritable grants interactive users Modify on the data dir so the
// user-session GUI can save socksit.yaml directly while the service is stopped.
// Secrets stay safe: creds.dpapi is DPAPI-encrypted and only SYSTEM can decrypt
// it. Best-effort (ignored if icacls is unavailable). BUILTIN\Users = S-1-5-32-545;
// (OI)(CI) so new files inherit the grant, M = Modify.
func ensureUserWritable(dir string) {
	_ = exec.Command("icacls", dir, "/grant", "*S-1-5-32-545:(OI)(CI)M", "/C", "/Q").Run()
}

// logf writes one timestamped, levelled line to the runtime log so SocksIt's own
// messages share a single parseable shape — "2006-01-02 15:04:05 LEVEL message"
// — alongside the engine's own formatted output. level is a short tag such as
// INFO, WARN or ERROR. Each call is a single Write, so lines never interleave.
func (r *Runtime) logf(level, format string, args ...any) {
	if r.log == nil {
		return
	}
	fmt.Fprintf(r.log, "%s %-5s %s\n", time.Now().Format("2006-01-02 15:04:05"), level, fmt.Sprintf(format, args...))
}

// safeMulti writes to every writer, ignoring individual errors so one dead sink
// (e.g. an absent console in the GUI-subsystem service) never blocks the others.
type safeMulti []io.Writer

func (m safeMulti) Write(p []byte) (int, error) {
	for _, w := range m {
		if w != nil {
			_, _ = w.Write(p)
		}
	}
	return len(p), nil
}

// --- ipc.Handler implementation ---

func (r *Runtime) Status() (any, error) {
	state := "disabled"
	pid := 0
	if r.enabled.Load() {
		if s := r.sup.Load(); s != nil {
			state = s.State().String()
			pid = s.CurrentPID()
		}
	}
	m := map[string]any{"enabled": r.enabled.Load(), "state": state, "pid": pid, "version": r.Version}
	// Add a config summary for the UI. This is read-only display data and never
	// includes secrets (credentials live only in the DPAPI blob, not the YAML).
	if b, err := os.ReadFile(r.configPath()); err == nil {
		c := config.ParseLenient(b)
		proxy := strings.TrimSpace(c.Proxy.Address)
		if proxy == "" {
			proxy = "(not set)"
		} else {
			proxy = net.JoinHostPort(proxy, strconv.Itoa(c.Proxy.Port))
		}
		m["proxy"] = proxy
		m["apps"] = len(c.Apps)
		m["mode"] = c.Mode
		m["kill_switch"] = c.KillSwitchOn()
		// Surface an available update so the tray can notify. Only in notify mode:
		// auto installs it itself, so there is nothing for the user to act on.
		if res := r.lastUpdate.Load(); res != nil && res.HasUpdate && strings.EqualFold(c.Update.Mode, config.UpdateNotify) {
			m["update_available"] = res.Available
		}
	}
	return m, nil
}

func (r *Runtime) GetConfig() (string, error) {
	b, err := os.ReadFile(r.configPath())
	return string(b), err
}

func (r *Runtime) SetConfig(yamlText string) error {
	cfg, err := config.Parse([]byte(yamlText))
	if err != nil {
		return err // reject invalid edits without touching the running config
	}
	// Clearing config_source.url in an edit means "go local": drop channel
	// remnants and unlock server-forced toggles before persisting.
	out := []byte(yamlText)
	if cfg.DemoteIfUnmanaged() {
		if b, mErr := yaml.Marshal(cfg); mErr == nil {
			out = b
		}
	}
	if err := os.WriteFile(r.configPath(), out, 0o600); err != nil {
		return err
	}
	r.signalRestart()
	return nil
}

func (r *Runtime) SetCredentials(user, pass string) error {
	b, _ := json.Marshal(creds{User: user, Pass: pass})
	if err := secretStore().SaveTo(r.credsPath(), string(b)); err != nil {
		return err
	}
	r.signalRestart()
	return nil
}

func (r *Runtime) Toggle(on bool) error {
	r.enabled.Store(on)
	r.signalRestart()
	return nil
}

func (r *Runtime) Reload() error {
	r.signalRestart()
	return nil
}

// Stats proxies the engine's Clash API connection list.
func (r *Runtime) Stats() (any, error) {
	cfg, err := config.Load(r.configPath())
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + cfg.Control.ClashAPI + "/connections")
	if err != nil {
		return nil, fmt.Errorf("engine not reachable: %w", err)
	}
	defer resp.Body.Close()
	var data json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return data, nil
}

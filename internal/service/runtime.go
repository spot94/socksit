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

	"socksit/internal/audit"
	"socksit/internal/config"
	"socksit/internal/engine"
	"socksit/internal/ipc"
	"socksit/internal/netstate"
	"socksit/internal/singbox"
	"socksit/internal/updates"
)

// credentialEntropy salts the DPAPI blob (defense in depth; see KTD7).
const credentialEntropy = "socksit-credentials-v1"

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
	lastUpdate atomic.Pointer[updates.Result]
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
	if lf, err := os.OpenFile(filepath.Join(r.DataDir, "socksit.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		r.log = safeMulti{r.log, lf}
		defer lf.Close()
	}
	if r.ensureFirstRunConfig() {
		fmt.Fprintf(r.log, "First run: created a default config at %s\n", r.configPath())
	}
	fmt.Fprintf(r.log,
		"SocksIt is starting.\n"+
			"  Config: %s\n"+
			"  Logs:   %s\n"+
			"  Edit settings in the app window — run `socksit gui`, or use the tray icon → \"Open app list…\".\n"+
			"  (You can also edit the config file directly; changes apply automatically.)\n",
		r.configPath(), r.DataDir)

	auditFile, _ := os.OpenFile(filepath.Join(r.DataDir, "audit.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if auditFile != nil {
		defer auditFile.Close()
	}
	auditLog := audit.New(orDiscard(auditFile))

	if needs, detail, err := netstate.Reconcile(); err == nil && needs {
		fmt.Fprintf(r.log, "reconcile: %s\n", detail)
		auditLog.Log("service", "reconciled stale network state", detail)
	}

	// Config hot-reload: editing socksit.yaml (or GUI Save) triggers a reload.
	if err := config.Watch(ctx, r.configPath(), 500*time.Millisecond, r.signalRestart); err != nil {
		fmt.Fprintf(r.log, "config watch unavailable: %v\n", err)
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
			fmt.Fprintf(r.log, "waiting for a valid config at %s — %v\n"+
				"  (edit the file: set proxy.address and add apps; changes apply automatically)\n",
				r.configPath(), err)
			if !r.waitRestart(ctx) {
				return ctx.Err()
			}
			continue
		}
		js, err := singbox.GenerateJSON(cfg)
		if err == nil {
			err = os.WriteFile(r.genPath(), js, 0o600)
		}
		if err == nil {
			err = singbox.Check(r.EnginePath, r.genPath())
		}
		if err != nil {
			fmt.Fprintf(r.log, "generate/check failed (keeping previous, holding): %v\n", err)
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
			<-done
			r.sup.Store(nil)
			return ctx.Err()
		case <-r.restartCh:
			cancel()
			<-done
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
	if u, p, ok := r.loadCreds(); ok {
		cfg.Proxy.Username, cfg.Proxy.Password = u, p
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
	}
	return cfg, nil
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
	def := "# SocksIt — set proxy.address and add apps, then save.\n" +
		"# Easiest: run `socksit gui`. Changes apply automatically.\n" +
		"proxy:\n  address: \"\"\n  port: 1080\napps: []\nmode: allowlist\nkill_switch: true\n"
	return os.WriteFile(r.configPath(), []byte(def), 0o600) == nil
}

// ensureUserWritable grants interactive users Modify on the data dir so the
// user-session GUI can save socksit.yaml directly while the service is stopped.
// Secrets stay safe: creds.dpapi is DPAPI-encrypted and only SYSTEM can decrypt
// it. Best-effort (ignored if icacls is unavailable). BUILTIN\Users = S-1-5-32-545;
// (OI)(CI) so new files inherit the grant, M = Modify.
func ensureUserWritable(dir string) {
	_ = exec.Command("icacls", dir, "/grant", "*S-1-5-32-545:(OI)(CI)M", "/C", "/Q").Run()
}

func orDiscard(w io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return io.Discard
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
	m := map[string]any{"enabled": r.enabled.Load(), "state": state, "pid": pid}
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
	}
	return m, nil
}

func (r *Runtime) GetConfig() (string, error) {
	b, err := os.ReadFile(r.configPath())
	return string(b), err
}

func (r *Runtime) SetConfig(yamlText string) error {
	if _, err := config.Parse([]byte(yamlText)); err != nil {
		return err // reject invalid edits without touching the running config
	}
	if err := os.WriteFile(r.configPath(), []byte(yamlText), 0o600); err != nil {
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

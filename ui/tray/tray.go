//go:build windows

// Package tray is the user-session notification-area app. It talks to the
// LocalSystem service over the IPC pipe (it never touches the TUN or secrets
// directly). See plan U9/KTD5/KTD10.
//
// The menu is intentionally minimal — live status, a proxying toggle, an "Open
// SocksIt" entry (the single-window control panel has everything else), and the
// version. Tray presence is bound to the service and the "Show in tray" setting:
// the service keeps a tray running while installed and enabled (see
// internal/service/traykeeper_windows.go), and the tray exits itself once the
// service is uninstalled or the setting is turned off. There is no manual "Quit".
package tray

import (
	_ "embed"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"

	"socksit/internal/config"
	"socksit/internal/ipc"
	"socksit/internal/service"
)

//go:embed icon.ico
var iconICO []byte

const callTimeout = 3 * time.Second

// singletonHandle holds the machine-global singleton mutex for the tray's
// lifetime; the OS releases it on process exit, letting the service keeper start
// a replacement.
var singletonHandle windows.Handle

// statusView mirrors the IPC status payload (internal/service Runtime.Status).
type statusView struct {
	Enabled bool   `json:"enabled"`
	State   string `json:"state"`
	Proxy   string `json:"proxy"`
	Version string `json:"version"` // the running service's build version
	// UpdateAvailable is the newer version the service found (notify mode only);
	// empty when up to date or in auto mode.
	UpdateAvailable string `json:"update_available"`
}

// notifiedVer is the last update version we showed a balloon for, so we notify
// once per version rather than every poll.
var notifiedVer string

// Run shows the tray and blocks until it quits. It is a singleton (a second
// instance exits immediately) and exits on its own once the service is
// uninstalled or "Show in tray" is turned off.
func Run(pipe, version string) {
	if !acquireSingleton() {
		return
	}
	systray.Run(func() { onReady(pipe, version) }, func() {})
}

// acquireSingleton returns true if this is the only tray. It keeps the mutex open
// for the process lifetime; a second instance sees ERROR_ALREADY_EXISTS and bows
// out.
func acquireSingleton() bool {
	name, err := windows.UTF16PtrFromString(service.TrayMutexName)
	if err != nil {
		return true
	}
	h, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return false
	}
	if err != nil {
		return true
	}
	singletonHandle = h
	return true
}

func onReady(pipe, version string) {
	systray.SetIcon(iconICO)
	systray.SetTitle("SocksIt")
	systray.SetTooltip("SocksIt — per-app SOCKS5")

	mStatus := systray.AddMenuItem("SocksIt — …", "Current state")
	mStatus.Disable()
	mUpdate := systray.AddMenuItem("", "A new version is available — click to open and install")
	mUpdate.Hide()
	systray.AddSeparator()
	mToggle := systray.AddMenuItemCheckbox("Proxying enabled", "Pause or resume proxying", true)
	systray.AddSeparator()
	mOpen := systray.AddMenuItem("Open SocksIt", "Open the control panel")
	systray.AddSeparator()
	mVersion := systray.AddMenuItem("SocksIt "+version, "Version (engine: sing-box v1.13.14)")
	mVersion.Disable()

	go pollStatus(pipe, version, mStatus, mToggle, mUpdate)

	go func() {
		for {
			select {
			case <-mToggle.ClickedCh:
				toggle(pipe)
			case <-mOpen.ClickedCh:
				launchSelf()
			case <-mUpdate.ClickedCh:
				launchSelf()
			}
		}
	}()
}

// launchSelf opens the control panel (this exe with no arguments).
func launchSelf() {
	if exe, err := os.Executable(); err == nil {
		_ = exec.Command(exe).Start()
	}
}

func pollStatus(pipe, version string, status, toggle, update *systray.MenuItem) {
	for {
		// Presence is bound to the service and the "Show in tray" setting.
		if installed, _, err := service.Status(); err == nil && !installed {
			systray.Quit()
			return
		}
		if !trayShowEnabled() {
			systray.Quit()
			return
		}
		if updateMenu(pipe, version, status, toggle, update) {
			// The service now runs a different build than this tray (an update was
			// applied) — exit so the keeper respawns a tray from the new binary.
			systray.Quit()
			return
		}
		time.Sleep(2 * time.Second)
	}
}

// updateMenu refreshes the menu from the service status and reports whether this
// tray is stale (the service reports a different build than our own version).
func updateMenu(pipe, version string, status, toggle, update *systray.MenuItem) (stale bool) {
	resp, err := ipc.Call(pipe, ipc.Request{Op: ipc.OpStatus}, callTimeout)
	if err != nil || !resp.OK {
		installed, running, _ := service.Status()
		head := "service unavailable"
		if installed && !running {
			head = "service stopped"
		}
		status.SetTitle("SocksIt — " + head)
		toggle.Uncheck()
		toggle.Disable()
		update.Hide()
		systray.SetTooltip("SocksIt — " + head)
		return false
	}
	var s statusView
	if json.Unmarshal(resp.Data, &s) != nil {
		status.SetTitle("SocksIt — unknown")
		update.Hide()
		return false
	}
	// A version mismatch means an update swapped the binary and restarted the
	// service; this tray is the old build and should hand off to a fresh one.
	if s.Version != "" && version != "" && s.Version != version {
		return true
	}
	toggle.Enable()
	if s.Enabled {
		toggle.Check()
	} else {
		toggle.Uncheck()
	}
	head := shortState(s)
	status.SetTitle("SocksIt — " + head)
	tip := "SocksIt — " + head
	if s.Proxy != "" && s.Proxy != "(not set)" {
		tip += " · " + s.Proxy
	}
	if s.UpdateAvailable != "" {
		update.SetTitle("↑ Update " + s.UpdateAvailable + " available — open")
		update.Show()
		tip += " · update " + s.UpdateAvailable
		if notifiedVer != s.UpdateAvailable {
			notifiedVer = s.UpdateAvailable
			showBalloon("SocksIt", "Update "+s.UpdateAvailable+" is available. Open SocksIt to install.")
		}
	} else {
		update.Hide()
	}
	systray.SetTooltip(tip)
	return false
}

// shortState renders a compact one-line state for the header and tooltip.
func shortState(s statusView) string {
	switch {
	case !s.Enabled:
		return "paused (proxying off)"
	case s.State == "running":
		return "active ✓"
	default:
		return "⚠ tunnel " + s.State + " — apps blocked"
	}
}

func toggle(pipe string) {
	resp, err := ipc.Call(pipe, ipc.Request{Op: ipc.OpStatus}, callTimeout)
	if err != nil {
		return
	}
	var s statusView
	_ = json.Unmarshal(resp.Data, &s)
	next := "true"
	if s.Enabled {
		next = "false"
	}
	_, _ = ipc.Call(pipe, ipc.Request{Op: ipc.OpToggle, Args: map[string]string{"on": next}}, callTimeout)
}

func dataDir() string    { return filepath.Join(os.Getenv("ProgramData"), "SocksIt") }
func configPath() string { return filepath.Join(dataDir(), "socksit.yaml") }

// trayShowEnabled reports the current "Show in tray" setting (default true when
// the config is unreadable).
func trayShowEnabled() bool {
	b, err := os.ReadFile(configPath())
	if err != nil {
		return true
	}
	return config.ParseLenient(b).ShowTrayEnabled()
}

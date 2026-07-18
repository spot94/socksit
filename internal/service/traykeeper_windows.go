//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"socksit/internal/config"
)

// TrayMutexName is the machine-global singleton guarding a single tray instance.
// The tray creates it; the keeper checks it to avoid launching a duplicate. It is
// in the Global\ namespace so the Session-0 service and the user-session tray see
// the same object.
const TrayMutexName = `Global\SocksItTray`

// superviseTray binds tray presence to the service: while the service runs, it
// ensures exactly one tray runs in the active console session, (re)launching it
// within a few seconds if it is missing (crash, kill, or a fresh logon). Combined
// with the tray exiting when the service is uninstalled (see ui/tray), this makes
// "service installed" and "tray present" inseparable. Best-effort: when no user
// is logged in yet it simply waits. Runs until ctx is cancelled.
func (r *Runtime) superviseTray(ctx context.Context) {
	exe, err := os.Executable()
	if err != nil {
		r.logf("WARN", "tray keeper disabled: %v", err)
		return
	}
	var lastErr string
	timer := time.NewTimer(2 * time.Second) // brief delay so the service settles first
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		// Honour the "Show in tray" setting: when off, don't launch (a running
		// tray notices the same setting and exits itself).
		if r.trayEnabled() && !trayRunning() {
			if err := launchTrayInActiveSession(exe); err != nil {
				// "no active console session" is the normal pre-logon case — log a
				// change once, not every tick.
				if s := err.Error(); s != lastErr {
					lastErr = s
					r.logf("WARN", "tray keeper: %v (will retry)", err)
				}
			} else {
				lastErr = ""
				r.logf("INFO", "tray keeper: launched tray in the console session")
			}
		}
		timer.Reset(7 * time.Second)
	}
}

// trayEnabled reports the current "Show in tray" setting from the config file
// (defaults to true when unreadable).
func (r *Runtime) trayEnabled() bool {
	b, err := os.ReadFile(r.configPath())
	if err != nil {
		return true
	}
	return config.ParseLenient(b).ShowTrayEnabled()
}

// trayRunning reports whether a tray instance currently holds the singleton mutex.
func trayRunning() bool {
	name, err := windows.UTF16PtrFromString(TrayMutexName)
	if err != nil {
		return false
	}
	h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, name)
	if err != nil {
		return false // does not exist -> no tray
	}
	windows.CloseHandle(h)
	return true
}

// launchTrayInActiveSession starts "socksit.exe tray" in the interactive console
// session as the logged-in user (the service itself runs as LocalSystem in
// session 0 and cannot show UI there).
func launchTrayInActiveSession(exe string) error {
	sess := windows.WTSGetActiveConsoleSessionId()
	if sess == 0xFFFFFFFF {
		return errors.New("no active console session")
	}
	var userTok windows.Token
	if err := windows.WTSQueryUserToken(sess, &userTok); err != nil {
		return fmt.Errorf("no interactive user yet: %w", err)
	}
	defer userTok.Close()

	var primary windows.Token
	if err := windows.DuplicateTokenEx(userTok, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityIdentification, windows.TokenPrimary, &primary); err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primary.Close()

	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, primary, false); err != nil {
		env = nil // fall back to the service's environment
	}
	defer func() {
		if env != nil {
			windows.DestroyEnvironmentBlock(env)
		}
	}()

	appName, _ := windows.UTF16PtrFromString(exe)
	cmdLine, _ := windows.UTF16PtrFromString(`"` + exe + `" tray`)
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)

	si := windows.StartupInfo{Desktop: desktop}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	if err := windows.CreateProcessAsUser(primary, appName, cmdLine, nil, nil, false,
		windows.CREATE_UNICODE_ENVIRONMENT, env, nil, &si, &pi); err != nil {
		return fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}

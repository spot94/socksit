//go:build windows

package service

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestShellRunning exercises the shell-readiness probe that gates the tray
// launch. This test host is an interactive desktop, so explorer.exe must be found
// in the active console session — and must NOT be found in a session that cannot
// have one.
func TestShellRunning(t *testing.T) {
	sess := windows.WTSGetActiveConsoleSessionId()
	if sess == 0xFFFFFFFF {
		t.Skip("no active console session (headless runner)")
	}
	if !shellRunning(sess) {
		t.Errorf("explorer.exe not detected in the active console session %d", sess)
	}
	// Session 0 is the service session: it never hosts the interactive shell.
	if sess != 0 && shellRunning(0) {
		t.Error("explorer.exe reported in session 0 — the probe ignores the session id")
	}
	// A session id that cannot exist must be reported as "no shell".
	if shellRunning(0xFFFFFFF0) {
		t.Error("expected no shell for a nonexistent session")
	}
}

// TestLaunchTrayWaitsForShellSettle verifies the settle window: right after the
// shell is first seen, launching is refused with a "still starting" error rather
// than spawning a tray whose icon would fail to register.
func TestLaunchTrayWaitsForShellSettle(t *testing.T) {
	if windows.WTSGetActiveConsoleSessionId() == 0xFFFFFFFF {
		t.Skip("no active console session (headless runner)")
	}
	saved := shellUpSince
	defer func() { shellUpSince = saved }()

	shellUpSince = time.Time{} // pretend we have just noticed the shell
	err := launchTrayInActiveSession("nonexistent.exe")
	if err == nil {
		t.Fatal("expected the first attempt to be refused during the settle window")
	}
	if !strings.Contains(err.Error(), "still starting") {
		t.Errorf("expected a settle-window error, got %v", err)
	}
}

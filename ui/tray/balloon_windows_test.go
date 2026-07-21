//go:build windows

package tray

import "testing"

// TestShowBalloonNoPanic exercises the syscall plumbing (proc resolution, struct
// sizing) without a systray window present: FindWindow returns 0 and showBalloon
// must return quietly rather than panic. It never asserts a balloon appears (that
// needs an interactive desktop).
func TestShowBalloonNoPanic(t *testing.T) {
	showBalloon("SocksIt", "Update 0.0.0 is available.")
}

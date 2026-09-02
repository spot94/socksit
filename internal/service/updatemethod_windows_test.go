//go:build windows

package service

import "testing"

// TestChooseUpdateMethod pins which update path is taken. The in-place exe swap
// — download a binary, rename the running one aside, restart the service — is
// the behaviour Kaspersky's PDM flags as a dropper, so the installer is used
// wherever it can be. It cannot be used everywhere: an install registered by
// `socksit install` has no MSI product to upgrade, and Windows Installer would
// fail registering a service that already exists and roll the update back.
func TestChooseUpdateMethod(t *testing.T) {
	cases := []struct {
		name            string
		hasMSI, fromMSI bool
		want            updateMethod
	}{
		{"installer available and this install came from one", true, true, updateViaMSI},
		{"installed by socksit install — msiexec would fail on the existing service", true, false, updateViaExe},
		{"older manifest without an installer", false, true, updateViaExe},
		{"neither", false, false, updateViaExe},
	}
	for _, c := range cases {
		if got := chooseUpdateMethod(c.hasMSI, c.fromMSI); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

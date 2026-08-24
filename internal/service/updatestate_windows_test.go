//go:build windows

package service

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestUpdateDueAcrossReboots is the case that motivated the persisted schedule:
// a PC switched off every night never stays up for 24h, so a timer-only schedule
// checked on every boot instead and check_interval meant nothing. What matters is
// the wall clock since the last check, not this process's uptime.
func TestUpdateDueAcrossReboots(t *testing.T) {
	now := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
	day := 24 * time.Hour

	if !updateDue(updateState{}, day, now) {
		t.Error("never checked — the first check must be due")
	}
	// Booted this morning, checked yesterday morning: due again.
	if !updateDue(updateState{LastCheck: now.Add(-25 * time.Hour)}, day, now) {
		t.Error("a check older than the interval must be due")
	}
	// Rebooted at lunch, checked at breakfast: NOT due (the old behaviour checked).
	if updateDue(updateState{LastCheck: now.Add(-3 * time.Hour)}, day, now) {
		t.Error("a reboot must not force a check inside the interval")
	}
	// A 7-day interval must actually mean 7 days.
	if updateDue(updateState{LastCheck: now.Add(-3 * day)}, 7*day, now) {
		t.Error("a longer interval must be honoured, not overridden by a restart")
	}
	// Clock moved backwards (RTC fixed, image restored): do not wait it out.
	if !updateDue(updateState{LastCheck: now.Add(2 * day)}, day, now) {
		t.Error("a last-check in the future must not park updates forever")
	}
}

func TestUpdateRetryGraceAfterFailure(t *testing.T) {
	now := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
	st := updateState{LastCheck: now.Add(-48 * time.Hour), LastFail: now.Add(-2 * time.Minute)}
	if updateDue(st, 24*time.Hour, now) {
		t.Error("a check that just failed must back off, not retry every tick")
	}
	st.LastFail = now.Add(-30 * time.Minute)
	if !updateDue(st, 24*time.Hour, now) {
		t.Error("after the grace, a failed check must be retried without waiting a full interval")
	}
}

// TestAutoRetryDoesNotDependOnHowTheMachineIsUsed: the attempt used to be
// remembered in memory, so a PC that reboots retried on every boot while a laptop
// that only sleeps never retried at all. Same policy for both now.
func TestAutoRetryDoesNotDependOnHowTheMachineIsUsed(t *testing.T) {
	now := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
	if !autoDue(updateState{}, "0.3.0", now) {
		t.Error("a version never tried must be allowed")
	}
	if autoDue(updateState{AutoVersion: "0.3.0", AutoAt: now.Add(-1 * time.Hour)}, "0.3.0", now) {
		t.Error("the same version must not be re-downloaded an hour later")
	}
	if !autoDue(updateState{AutoVersion: "0.3.0", AutoAt: now.Add(-7 * time.Hour)}, "0.3.0", now) {
		t.Error("a transient failure must get another go once the grace has passed")
	}
	if !autoDue(updateState{AutoVersion: "0.3.0", AutoAt: now}, "0.3.1", now) {
		t.Error("a different version is a different decision")
	}
}

// TestUpdateStateFailsOpen: a corrupt or unreadable state file must not be able
// to stop updates — the zero value makes the next check due.
func TestUpdateStateFailsOpen(t *testing.T) {
	r := &Runtime{DataDir: t.TempDir()}
	if got := r.loadUpdateState(); !got.LastCheck.IsZero() {
		t.Errorf("a missing file must read as never checked, got %+v", got)
	}
	if err := os.WriteFile(filepath.Join(r.DataDir, "update-state.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := r.loadUpdateState(); !got.LastCheck.IsZero() {
		t.Errorf("a corrupt file must read as never checked, got %+v", got)
	}
	if !updateDue(r.loadUpdateState(), 24*time.Hour, time.Now()) {
		t.Error("a corrupt file must leave the next check due")
	}

	want := updateState{LastCheck: time.Now().UTC().Truncate(time.Second), AutoVersion: "0.3.0"}
	r.saveUpdateState(want)
	got := r.loadUpdateState()
	if !got.LastCheck.Equal(want.LastCheck) || got.AutoVersion != want.AutoVersion {
		t.Errorf("round-trip lost state: %+v vs %+v", got, want)
	}
}

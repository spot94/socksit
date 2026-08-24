//go:build windows

package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// updateState is what the update schedule has to remember across restarts.
//
// It exists because the schedule used to be a single long timer, which meant
// check_interval only ever applied to a machine that stayed up that long. A PC
// switched off overnight never reached 24h of uptime, so the interval never
// fired and the real cadence was "once per boot, 30s in" — five reboots meant
// five checks, and a 7-day interval meant nothing at all. Keeping the times on
// disk lets one setting mean the same thing across reboots, sleep and edits.
type updateState struct {
	// LastCheck is the last check that actually reached the endpoint.
	LastCheck time.Time `json:"last_check,omitempty"`
	// LastFail is the last check that did not. Kept separately so a broken
	// endpoint is retried on a short grace instead of either hammering it every
	// tick or going quiet for the whole interval.
	LastFail time.Time `json:"last_fail,omitempty"`
	// AutoVersion/AutoAt record what auto mode last tried to install. Persisted
	// rather than held in memory: in memory the retry policy silently depended on
	// how the machine is used — a PC that reboots retried on every boot, while a
	// laptop that only sleeps never retried at all.
	AutoVersion string    `json:"auto_version,omitempty"`
	AutoAt      time.Time `json:"auto_at,omitempty"`
}

const (
	// updateTick is how often the schedule wakes to ask "is it due yet?".
	updateTick = 5 * time.Minute
	// updateSettle delays the first tick so a boot-time check does not compete
	// with the tunnel coming up.
	updateSettle = 30 * time.Second
	// updateRetryGrace is how long to leave a failing endpoint alone. Short,
	// because a failed check usually means the network was not ready yet.
	updateRetryGrace = 15 * time.Minute
	// autoRetryGrace bounds auto mode's retries of the same version: enough that
	// a transient failure (network, a locked exe) gets another go, not so little
	// that a genuinely bad release is downloaded over and over.
	autoRetryGrace = 6 * time.Hour
)

func (r *Runtime) updateStatePath() string {
	return filepath.Join(r.DataDir, "update-state.json")
}

// loadUpdateState reads the schedule state. A missing or unreadable file is not
// an error: the zero value means "never checked", which makes the next tick due.
// Failing open matters — a corrupt file must not be able to stop updates.
func (r *Runtime) loadUpdateState() updateState {
	var st updateState
	b, err := os.ReadFile(r.updateStatePath())
	if err != nil {
		return st
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return updateState{}
	}
	return st
}

func (r *Runtime) saveUpdateState(st updateState) {
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	if err := os.WriteFile(r.updateStatePath(), b, 0o600); err != nil {
		r.logf("WARN", "update: could not record the check schedule: %v", err)
	}
}

// updateDue reports whether a check should run now.
func updateDue(st updateState, every time.Duration, now time.Time) bool {
	if !st.LastFail.IsZero() && now.Sub(st.LastFail) < updateRetryGrace {
		return false
	}
	if st.LastCheck.IsZero() {
		return true
	}
	since := now.Sub(st.LastCheck)
	// A negative gap means the clock moved back (a fixed RTC, a timezone-confused
	// image). Check rather than wait out an interval that may never elapse.
	return since < 0 || since >= every
}

// autoDue reports whether auto mode may (re)try this version.
func autoDue(st updateState, version string, now time.Time) bool {
	if st.AutoVersion != version {
		return true
	}
	return now.Sub(st.AutoAt) >= autoRetryGrace
}

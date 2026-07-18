//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"socksit/internal/updates"
)

// detachedFlags start the restart helper as an independent process that survives
// the service stopping: DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP.
const detachedFlags = 0x00000008 | 0x00000200

type applyResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// UpdateApply downloads the newer signed release, swaps in the new socksit.exe,
// and spawns a detached helper that restarts the service (with rollback). Errors
// are folded into the payload so the UI always gets a result.
func (r *Runtime) UpdateApply() (any, error) {
	res, err := r.applyUpdate()
	if err != nil {
		return applyResult{false, err.Error()}, nil
	}
	return res, nil
}

func (r *Runtime) applyUpdate() (applyResult, error) {
	cfg := r.lenientConfig()
	client, err := r.buildUpdateClient(cfg)
	if err != nil {
		return applyResult{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	m, err := updates.Fetch(ctx, client, cfg.Update.Endpoint, cfg.Update.Channel)
	if err != nil {
		return applyResult{}, err
	}
	if !updates.Newer(m.Version, r.Version) {
		return applyResult{true, "already up to date (" + r.Version + ")"}, nil
	}
	if m.App.URL == "" || m.App.SHA256 == "" {
		return applyResult{}, errors.New("the manifest has no app artifact to download")
	}

	fmt.Fprintf(r.log, "update: downloading %s from %s\n", m.Version, m.App.URL)
	appBytes, err := updates.DownloadVerified(ctx, client, m.App.URL, m.App.SHA256)
	if err != nil {
		return applyResult{}, err
	}

	// Swap the installed exe: rename the running one aside, write the new one in
	// its place. Renaming a running exe is allowed on Windows.
	target := filepath.Join(InstallDir(), "socksit.exe")
	oldPath := target + ".old"
	_ = os.Remove(oldPath)
	if err := os.Rename(target, oldPath); err != nil {
		return applyResult{}, fmt.Errorf("set aside the current exe: %w", err)
	}
	if err := os.WriteFile(target, appBytes, 0o755); err != nil {
		_ = os.Rename(oldPath, target) // undo
		return applyResult{}, fmt.Errorf("write the new exe: %w", err)
	}
	fmt.Fprintf(r.log, "update: installed %s, launching restart helper\n", m.Version)

	// Spawn the KNOWN-GOOD old binary as a detached helper to stop→start the
	// service and roll back if the new build fails to come up.
	cmd := exec.Command(oldPath, "update-restart", "-service", ServiceName, "-target", target, "-old", oldPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedFlags}
	if err := cmd.Start(); err != nil {
		_ = os.Remove(target) // undo the swap
		_ = os.Rename(oldPath, target)
		return applyResult{}, fmt.Errorf("start the restart helper: %w", err)
	}
	return applyResult{true, "Update " + m.Version + " downloaded — the service will restart to apply it."}, nil
}

// RunUpdateRestart is the detached helper: it stops the service, starts the new
// version, verifies it reaches Running, and rolls back from oldPath on failure.
// It runs as SYSTEM (spawned by the service) and outlives the old service process.
func RunUpdateRestart(serviceName, target, oldPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	_, _ = s.Control(svc.Stop)
	waitState(s, svc.Stopped, 40*time.Second)

	startErr := s.Start()
	if startErr == nil {
		waitState(s, svc.Running, 40*time.Second)
	}
	if st, _ := s.Query(); startErr == nil && st.State == svc.Running {
		_ = os.Remove(oldPath) // success — drop the backup
		return nil
	}

	// Health-check failed → roll back to the previous binary.
	_, _ = s.Control(svc.Stop)
	waitState(s, svc.Stopped, 40*time.Second)
	_ = os.Remove(target + ".failed")
	_ = os.Rename(target, target+".failed") // keep the bad build for inspection
	if err := os.Rename(oldPath, target); err != nil {
		return fmt.Errorf("rollback: restore previous exe: %w", err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("rollback: start service: %w", err)
	}
	return errors.New("update failed to start; rolled back to the previous version")
}

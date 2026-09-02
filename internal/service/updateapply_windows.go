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

	"golang.org/x/sys/windows/registry"
	"net/http"
	"socksit/internal/updates"
	"strings"
)

// detachedFlags start the restart helper as an independent process that survives
// the service stopping: DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP.
const detachedFlags = 0x00000008 | 0x00000200

type applyResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	// Applied is true only when a new binary was actually swapped in and the
	// restart helper spawned (not for "already up to date"). The panel uses it to
	// decide whether to relaunch itself into the new binary.
	Applied bool `json:"applied"`
}

// UpdateApply downloads the newer signed release, swaps in the new socksit.exe,
// and spawns a detached helper that restarts the service (with rollback). Errors
// are folded into the payload so the UI always gets a result.
func (r *Runtime) UpdateApply() (any, error) {
	res, err := r.applyUpdate()
	if err != nil {
		return applyResult{OK: false, Message: err.Error()}, nil
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
		return applyResult{OK: true, Message: "already up to date (" + r.Version + ")"}, nil
	}
	if chooseUpdateMethod(m.MSI.URL != "" && m.MSI.SHA256 != "", installedFromMSI()) == updateViaMSI {
		return r.applyUpdateMSI(ctx, client, m)
	}
	if m.App.URL == "" || m.App.SHA256 == "" {
		return applyResult{}, errors.New("the manifest has no app artifact to download")
	}

	r.logf("INFO", "update: downloading %s from %s", m.Version, m.App.URL)
	appBytes, err := updates.DownloadVerified(ctx, client, m.App.URL, m.App.SHA256)
	if err != nil {
		return applyResult{}, err
	}

	// Swap the installed exe: rename the running one aside, write the new one in
	// its place. Renaming a running exe is itself allowed on Windows; the failure
	// mode is a *leftover* socksit.exe.old still locked by a lingering old process
	// (e.g. a previous panel/tray that didn't exit) or by antivirus — then
	// replacing it fails with "Access is denied". Use a fresh backup name so we
	// never have to replace a locked .old, and retry to ride out transient locks.
	target := filepath.Join(InstallDir(), "socksit.exe")
	oldPath := freshBackupPath(target)
	if err := renameWithRetry(target, oldPath); err != nil {
		return applyResult{}, fmt.Errorf("set aside the current exe — %s may be locked by a leftover SocksIt process or antivirus (close SocksIt windows or reboot, then retry): %w", target, err)
	}
	if err := os.WriteFile(target, appBytes, 0o755); err != nil {
		_ = os.Rename(oldPath, target) // undo
		return applyResult{}, fmt.Errorf("write the new exe: %w", err)
	}
	r.logf("INFO", "update: installed %s, launching restart helper", m.Version)

	// Spawn the KNOWN-GOOD old binary as a detached helper to stop→start the
	// service and roll back if the new build fails to come up.
	cmd := exec.Command(oldPath, "update-restart", "-service", ServiceName, "-target", target, "-old", oldPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedFlags}
	if err := cmd.Start(); err != nil {
		_ = os.Remove(target) // undo the swap
		_ = os.Rename(oldPath, target)
		return applyResult{}, fmt.Errorf("start the restart helper: %w", err)
	}
	return applyResult{OK: true, Applied: true, Message: "Update " + m.Version + " downloaded — the service will restart to apply it."}, nil
}

// freshBackupPath returns where to move the current exe aside. It prefers
// "<target>.old", but if that already exists and can't be removed (a lingering
// old process is holding it), it falls back to a unique per-attempt name so the
// move never has to replace a locked file — the historical cause of "rename …
// Access is denied" during an update.
func freshBackupPath(target string) string {
	p := target + ".old"
	if err := os.Remove(p); err == nil || errors.Is(err, os.ErrNotExist) {
		return p
	}
	return fmt.Sprintf("%s.old-%d", target, os.Getpid())
}

// renameWithRetry renames from->to, retrying briefly so a transient lock (e.g. an
// antivirus scanning the file) doesn't fail the whole update on the first try.
func renameWithRetry(from, to string) error {
	var err error
	for i := 0; i < 8; i++ {
		if err = os.Rename(from, to); err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return err
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

// updateMethod is how an update gets applied. Two paths exist because the
// installer can only upgrade what it installed.
type updateMethod string

const (
	updateViaMSI updateMethod = "msi" // Windows Installer: stops the service, swaps files, rolls back on failure
	updateViaExe updateMethod = "exe" // in-place swap of the running exe, with our own restart helper
)

// chooseUpdateMethod prefers the installer when both sides support it.
//
// The exe swap — download a binary, rename the running one aside, write the new
// one, restart the service — is indistinguishable from what a dropper does, and
// behavioural AV (Kaspersky's PDM) flags it. An msiexec upgrade is the shape
// Windows expects: a trusted Microsoft binary drives it, the service stop/start
// is declared rather than improvised, and a failed install rolls back on its own.
//
// It only works where there is a product to upgrade. An install registered by
// `socksit install` has no MSI inventory entry, so ServiceInstall would hit the
// existing service, fail, and roll the whole thing back — those keep the swap.
func chooseUpdateMethod(manifestHasMSI, installedFromMSI bool) updateMethod {
	if manifestHasMSI && installedFromMSI {
		return updateViaMSI
	}
	return updateViaExe
}

// installedFromMSI reads the marker the installer writes (see build/installer.wxs).
func installedFromMSI() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\SocksIt`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue("InstalledBy")
	return err == nil && strings.EqualFold(strings.TrimSpace(v), "msi")
}

// applyUpdateMSI downloads the installer and hands it to msiexec, detached: the
// install stops this very service, so nothing after the spawn is guaranteed to
// run. Everything that must be recorded is recorded before it.
func (r *Runtime) applyUpdateMSI(ctx context.Context, client *http.Client, m updates.Manifest) (applyResult, error) {
	dir := filepath.Join(r.DataDir, "update")
	_ = os.RemoveAll(dir) // a previous attempt's package is dead weight (~50 MB)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return applyResult{}, fmt.Errorf("prepare the update directory: %w", err)
	}
	r.logf("INFO", "update: downloading installer %s from %s", m.Version, m.MSI.URL)
	body, err := updates.DownloadVerified(ctx, client, m.MSI.URL, m.MSI.SHA256)
	if err != nil {
		return applyResult{}, err
	}
	pkg := filepath.Join(dir, "SocksIt-"+m.Version+".msi")
	if err := os.WriteFile(pkg, body, 0o600); err != nil {
		return applyResult{}, fmt.Errorf("write the installer: %w", err)
	}
	logPath := filepath.Join(dir, "msiexec.log")
	r.logf("INFO", "update: installing %s via msiexec (log: %s)", m.Version, logPath)

	cmd := exec.Command("msiexec.exe", "/i", pkg, "/qn", "/norestart", "/l*v", logPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedFlags}
	if err := cmd.Start(); err != nil {
		return applyResult{}, fmt.Errorf("start msiexec: %w", err)
	}
	return applyResult{OK: true, Applied: true,
		Message: "Installer " + m.Version + " downloaded — Windows Installer is applying it and will restart the service."}, nil
}

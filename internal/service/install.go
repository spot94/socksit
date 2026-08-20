//go:build windows

package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"socksit/assets"
	"socksit/internal/config"
	"socksit/internal/enginedl"
)

// InstallDir is the stable location the service runs from: %ProgramFiles%\SocksIt.
func InstallDir() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "SocksIt")
}

// Install copies socksit.exe (and, for non-embedded builds, the sing-box engine)
// into the stable install dir and registers the service to run that copy as
// LocalSystem with automatic start. Because the copy lives in a fixed location,
// moving the original binary afterwards does not break the service. Requires
// administrator rights (writes to Program Files + registers the service).
func Install(currentExe string) error {
	dir := InstallDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create install dir %s: %w", dir, err)
	}
	target := filepath.Join(dir, "socksit.exe")

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(ServiceName); err == nil {
		s.Close()
		return fmt.Errorf("service %q already installed (uninstall first)", ServiceName)
	}

	// Copy the binary into the stable dir (skip if we're already running from it).
	if !samePath(currentExe, target) {
		if err := copyFile(currentExe, target); err != nil {
			return fmt.Errorf("copy binary to %s: %w", target, err)
		}
	}
	// Place the engine beside it. Embedded builds self-extract at runtime, so
	// only non-embedded builds need the engine copied here.
	if !assets.Embedded() {
		enginePath := filepath.Join(dir, "sing-box.exe")
		if src := locateEngine(currentExe); src != "" {
			if err := copyFile(src, enginePath); err != nil {
				return fmt.Errorf("copy engine: %w", err)
			}
		} else {
			// No local engine: download a verified sing-box.exe so a bare
			// socksit.exe is self-sufficient (official source, SocksIt fallback).
			client, err := engineDownloadClient()
			if err != nil {
				return fmt.Errorf("prepare engine download: %w", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if err := enginedl.Ensure(ctx, client, enginePath); err != nil {
				return fmt.Errorf("sing-box.exe was not found next to %s and could not be downloaded: %w", currentExe, err)
			}
		}
		// Never register the service around an unusable engine: a zero-byte file
		// fails at launch with "not a valid Win32 application", which is opaque.
		if fi, err := os.Stat(enginePath); err != nil || fi.Size() == 0 {
			_ = os.Remove(enginePath)
			return fmt.Errorf("staged engine at %s is unusable (empty) — remove it and run Set up again", enginePath)
		}
	}

	s, err := m.CreateService(ServiceName, target, mgr.Config{
		DisplayName:      "SocksIt per-app SOCKS5 proxifier",
		StartType:        mgr.StartAutomatic,
		ServiceStartName: "LocalSystem",
	}, "service")
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()
	return nil
}

// locateEngine finds sing-box.exe near the given binary (or in assets/bin).
// locateEngine finds an engine to stage. A zero-byte file is treated as absent:
// a previously truncated sing-box.exe must not be "copied" over itself again,
// and falling through to the download path repairs the install.
func locateEngine(exe string) string {
	dir := filepath.Dir(exe)
	for _, c := range []string{
		filepath.Join(dir, "sing-box.exe"),
		filepath.Join(dir, "assets", "bin", "sing-box.exe"),
		filepath.Join("assets", "bin", "sing-box.exe"),
	} {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() && fi.Size() > 0 {
			return c
		}
	}
	return ""
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func samePath(a, b string) bool {
	pa, _ := filepath.Abs(a)
	pb, _ := filepath.Abs(b)
	return strings.EqualFold(filepath.Clean(pa), filepath.Clean(pb))
}

// copyFile copies src over dst. It refuses to copy a file onto itself — that
// used to truncate the source to zero bytes (os.Create implies O_TRUNC, so the
// file was emptied before being read) and is how a re-install produced a 0-byte
// sing-box.exe. It also stages through a temporary file next to dst and renames
// it into place, so an interrupted copy leaves the previous file intact instead
// of a truncated one.
func copyFile(src, dst string) error {
	if samePath(src, dst) {
		return nil // already in place; copying would destroy it
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".socksit-copy-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeded
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Windows will not rename onto an existing file.
	_ = os.Remove(dst)
	return os.Rename(tmpName, dst)
}

// engineDownloadClient builds an HTTP client for the on-demand engine download,
// honoring the configured update proxy (and any stored SOCKS5 credentials, for
// update.proxy = use-socks).
func engineDownloadClient() (*http.Client, error) {
	dd := DataDir()
	cfg := config.Default()
	if b, err := os.ReadFile(filepath.Join(dd, "socksit.yaml")); err == nil {
		cfg = config.ParseLenient(b)
	}
	return updateHTTPClient(cfg.Update.Proxy, cfg, loadStoredCreds(dd))
}

// Uninstall stops and removes the service.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %q not installed", ServiceName)
	}
	defer s.Close()

	if status, err := s.Control(svc.Stop); err == nil {
		// give it a moment to stop before deletion
		deadline := time.Now().Add(10 * time.Second)
		for status.State != svc.Stopped && time.Now().Before(deadline) {
			time.Sleep(300 * time.Millisecond)
			if status, err = s.Query(); err != nil {
				break
			}
		}
	}
	return s.Delete()
}

// Start starts the installed service. Requires administrator rights.
func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %q not installed", ServiceName)
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	waitState(s, svc.Running, 15*time.Second) // settle so callers see the real state
	return nil
}

// Stop stops the running service. Requires administrator rights.
func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %q not installed", ServiceName)
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	waitState(s, svc.Stopped, 15*time.Second) // settle so callers see the real state
	return nil
}

// waitState polls until the service reaches target or the timeout elapses.
func waitState(s *mgr.Service, target svc.State, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil || st.State == target {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// Status reports whether the service is installed and running. It uses minimal
// access rights, so it works without administrator elevation.
func Status() (installed, running bool, err error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, false, fmt.Errorf("open SCM: %w", err)
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(ServiceName)
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false, false, nil // ERROR_SERVICE_DOES_NOT_EXIST -> not installed
	}
	defer windows.CloseServiceHandle(h)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(h, &st); err != nil {
		return true, false, fmt.Errorf("query status: %w", err)
	}
	return true, st.CurrentState == windows.SERVICE_RUNNING, nil
}

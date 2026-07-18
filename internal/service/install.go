//go:build windows

package service

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"socksit/assets"
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
		src := locateEngine(currentExe)
		if src == "" {
			return fmt.Errorf("sing-box.exe not found next to %s — keep it alongside socksit.exe, or build with -tags embed_engine", currentExe)
		}
		if err := copyFile(src, filepath.Join(dir, "sing-box.exe")); err != nil {
			return fmt.Errorf("copy engine: %w", err)
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
func locateEngine(exe string) string {
	dir := filepath.Dir(exe)
	for _, c := range []string{
		filepath.Join(dir, "sing-box.exe"),
		filepath.Join(dir, "assets", "bin", "sing-box.exe"),
		filepath.Join("assets", "bin", "sing-box.exe"),
	} {
		if fileExists(c) {
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

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
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

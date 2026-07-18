//go:build windows

package engine

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func stagedEngine(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SOCKSIT_ENGINE"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	cand := filepath.Join("..", "..", "assets", "bin", "sing-box.exe")
	if _, err := os.Stat(cand); err == nil {
		abs, _ := filepath.Abs(cand)
		return abs
	}
	return ""
}

// loopbackConfig writes a minimal, admin-free engine config (a mixed inbound on
// 127.0.0.1:port -> direct) so the supervisor can be exercised without a TUN.
func loopbackConfig(t *testing.T, port int) string {
	t.Helper()
	js := fmt.Sprintf(`{
	  "log": {"level":"warn"},
	  "dns": {"servers":[{"type":"local","tag":"local"}]},
	  "inbounds": [{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":%d}],
	  "outbounds": [{"type":"direct","tag":"direct"}],
	  "route": {"default_domain_resolver":{"server":"local"},"final":"direct"}
	}`, port)
	p := filepath.Join(t.TempDir(), "loopback.json")
	if err := os.WriteFile(p, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func portOpen(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func TestSupervisorRestartAndTeardown(t *testing.T) {
	eng := stagedEngine(t)
	if eng == "" {
		t.Skip("sing-box engine not staged; skipping supervisor integration test")
	}
	const port = 18091
	addr := "127.0.0.1:" + strconv.Itoa(port)
	if portOpen(addr) {
		t.Skipf("port %d already in use", port)
	}

	logf, _ := os.CreateTemp(t.TempDir(), "engine-*.log")
	if logf != nil {
		defer logf.Close()
	}
	sup := New(Options{
		EnginePath: eng,
		ConfigPath: loopbackConfig(t, port),
		ReadyAddr:  addr,
		Stdout:     logf,
		MinBackoff: 100 * time.Millisecond,
		HealthyFor: 500 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	// 1) engine comes up
	if !waitFor(t, 15*time.Second, func() bool { return sup.State() == StateRunning && portOpen(addr) }) {
		cancel()
		t.Fatalf("engine did not reach Running; state=%s", sup.State())
	}
	pid1 := sup.CurrentPID()
	if pid1 == 0 {
		cancel()
		t.Fatal("expected a non-zero engine pid")
	}

	// 2) kill the child externally -> supervisor must restart it with a new pid
	if err := exec.Command("taskkill", "/F", "/PID", strconv.Itoa(pid1)).Run(); err != nil {
		t.Logf("taskkill returned: %v (continuing)", err)
	}
	if !waitFor(t, 15*time.Second, func() bool {
		p := sup.CurrentPID()
		return p != 0 && p != pid1 && sup.State() == StateRunning && portOpen(addr)
	}) {
		cancel()
		t.Fatalf("engine did not restart with a new pid; state=%s pid=%d (was %d)", sup.State(), sup.CurrentPID(), pid1)
	}

	// 3) cancel -> deterministic teardown, port closes, Run returns
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("supervisor did not return after cancel")
	}
	if !waitFor(t, 5*time.Second, func() bool { return !portOpen(addr) }) {
		t.Errorf("engine port still open after teardown (possible orphan)")
	}
}

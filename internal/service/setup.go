//go:build windows

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"socksit/internal/config"
	"socksit/internal/preset"
)

// DataDir is the fixed per-machine data location (config, logs, secrets).
func DataDir() string { return filepath.Join(os.Getenv("ProgramData"), "SocksIt") }

// Setup performs the turnkey install for an end user: install the service into
// the stable dir (if not already), apply the bundled/sibling preset config (if
// any), and start the service. It is idempotent and requires administrator
// rights. Returns a human-readable summary of what it did.
func Setup(currentExe string) (string, error) {
	var steps []string

	installed, _, _ := Status()
	if !installed {
		if err := Install(currentExe); err != nil {
			return "", err
		}
		steps = append(steps, "installed service to "+InstallDir())
	} else {
		steps = append(steps, "service already installed")
	}

	if data, src, ok := preset.Load(filepath.Dir(currentExe)); ok {
		if _, err := config.Parse(data); err != nil {
			return "", fmt.Errorf("preset config is invalid: %w", err)
		}
		dd := DataDir()
		if err := os.MkdirAll(dd, 0o755); err != nil {
			return "", fmt.Errorf("create data dir: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dd, "socksit.yaml"), data, 0o600); err != nil {
			return "", fmt.Errorf("write config: %w", err)
		}
		steps = append(steps, "applied preset ("+src+")")
	} else {
		steps = append(steps, "no preset found — configure via Edit settings")
	}

	if _, running, _ := Status(); !running {
		if err := Start(); err != nil {
			return "", fmt.Errorf("start service: %w", err)
		}
		steps = append(steps, "started service")
	} else {
		steps = append(steps, "service running (config reloaded)")
	}

	return strings.Join(steps, "; "), nil
}

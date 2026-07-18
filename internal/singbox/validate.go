package singbox

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Check validates a config.json on disk with `sing-box check`. It must pass
// before the supervisor launches the engine.
func Check(enginePath, configPath string) error {
	cmd := exec.Command(enginePath, "check", "-c", configPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sing-box check failed (%v): %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}

// CheckBytes writes cfg to a temp file and validates it, cleaning up after.
func CheckBytes(enginePath string, cfg []byte) error {
	f, err := os.CreateTemp("", "socksit-check-*.json")
	if err != nil {
		return fmt.Errorf("temp config: %w", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(cfg); err != nil {
		f.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	return Check(enginePath, f.Name())
}

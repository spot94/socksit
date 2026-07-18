//go:build embed_engine

// Package assets optionally embeds the sing-box engine so a release build is a
// single self-contained binary. Built with -tags embed_engine, the engine is
// compiled in and extracted at runtime; the default build omits it (lean dev
// builds) and uses the staged assets/bin/sing-box.exe or the installer-bundled
// copy. See plan U2/KTD1.
package assets

import (
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed bin/sing-box.exe
var singBox []byte

// Embedded reports whether the engine is compiled into this binary.
func Embedded() bool { return true }

// Extract writes the embedded engine into dir and returns the sing-box path.
// It is idempotent: an already-extracted file of the same size is left as is.
func Extract(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	engine := filepath.Join(dir, "sing-box.exe")
	if err := writeIfChanged(engine, singBox); err != nil {
		return "", err
	}
	return engine, nil
}

func writeIfChanged(path string, data []byte) error {
	if fi, err := os.Stat(path); err == nil && fi.Size() == int64(len(data)) {
		return nil
	}
	return os.WriteFile(path, data, 0o755)
}

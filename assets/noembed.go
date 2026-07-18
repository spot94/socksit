//go:build !embed_engine

package assets

import "errors"

// Embedded reports whether the engine is compiled in (false in the default build).
func Embedded() bool { return false }

// Extract is a no-op in the default build; callers fall back to the staged
// engine path (assets/bin/sing-box.exe) or the installer-bundled copy.
func Extract(string) (string, error) {
	return "", errors.New("engine not embedded (build with -tags embed_engine)")
}

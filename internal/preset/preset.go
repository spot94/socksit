// Package preset supplies an optional pre-baked configuration for turnkey
// installer builds, so an end user needs no manual setup. The preset comes from
// one of two sources (checked in order): compiled into the binary
// (build -tags preset), or a sibling socksit.preset.yaml next to the executable.
// `socksit setup` (and the control panel's Set up button) apply it.
package preset

import (
	"os"
	"path/filepath"
)

// SiblingName is the external preset file looked for next to the executable.
const SiblingName = "socksit.preset.yaml"

// Load returns the preset config bytes and a description of its source.
// Precedence: build-time embedded preset, then a sibling socksit.preset.yaml.
func Load(exeDir string) (data []byte, source string, ok bool) {
	if b := embedded(); len(b) > 0 {
		return b, "embedded", true
	}
	p := filepath.Join(exeDir, SiblingName)
	if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
		return b, p, true
	}
	return nil, "", false
}

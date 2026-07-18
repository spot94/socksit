//go:build preset

package preset

import _ "embed"

// presetYAML is the configuration baked in for a turnkey build. Edit
// internal/preset/preset.yaml before building with -tags preset.
//
//go:embed preset.yaml
var presetYAML []byte

func embedded() []byte { return presetYAML }

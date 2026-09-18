package preset

import (
	"os"
	"testing"

	"socksit/internal/config"
)

// Both presets are written straight into socksit.yaml by Setup, so an invalid
// one fails the install on a user's machine. The shipped template had drifted a
// year behind the schema before anyone noticed; this keeps them honest.
func TestPresetsValidate(t *testing.T) {
	for _, p := range []string{"preset.yaml", "../../build/preset.example.yaml"} {
		t.Run(p, func(t *testing.T) {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := config.Parse(b); err != nil {
				t.Fatalf("does not validate: %v", err)
			}
			// A key the schema does not know is silently ignored at runtime, which
			// in a preset means a setting the admin believes they deployed.
			if unknown := config.UnknownKeys(b); len(unknown) > 0 {
				t.Errorf("unrecognised keys: %v", unknown)
			}
		})
	}
}

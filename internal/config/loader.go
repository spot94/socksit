package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads, defaults, and validates a socksit.yaml at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// ParseLenient decodes YAML applying defaults but skipping validation, and never
// returns an error. It is for read-only display (e.g. the status summary), where
// an incomplete or not-yet-valid config should still surface whatever fields are
// present. Unknown keys are ignored.
func ParseLenient(data []byte) *Config {
	var c Config
	_ = yaml.Unmarshal(data, &c)
	c.applyDefaults()
	return &c
}

// Parse decodes, applies defaults, and validates a config from YAML bytes.
//
// Unknown keys are deliberately IGNORED rather than rejected. The config file is
// shared between components that can be at different versions — the service may
// be newer than the panel, an update can be rolled back, and a managed feed may
// come from a newer config server. A newer SocksIt writes keys an older one has
// never heard of (bypass_cidrs was the first to bite), and rejecting them here
// took down the whole datapath: the service refused to load its own config and
// the panel reported "config is not valid yet". Typos are still catchable — call
// UnknownKeys, which the CLI's `config validate` and the panel's diagnostics
// report as a warning.
func Parse(data []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &c, nil
}

// UnknownKeys reports keys this build does not recognise (a typo, or a config
// written by a newer SocksIt). Advisory only — Parse accepts them.
func UnknownKeys(data []byte) []string {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	err := dec.Decode(&c)
	if err == nil {
		return nil
	}
	te, ok := err.(*yaml.TypeError)
	if !ok {
		return nil // a real syntax error — Parse reports it
	}
	var out []string
	for _, m := range te.Errors {
		// yaml.v3: `line 19: field bypass_cidrs not found in type config.Config`
		if i := strings.Index(m, "field "); i >= 0 {
			rest := m[i+len("field "):]
			if j := strings.Index(rest, " not found"); j > 0 {
				out = append(out, rest[:j])
				continue
			}
		}
		out = append(out, m)
	}
	return out
}

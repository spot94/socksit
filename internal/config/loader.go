package config

import (
	"bytes"
	"fmt"
	"os"

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
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // reject unknown keys so typos are caught early
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &c, nil
}

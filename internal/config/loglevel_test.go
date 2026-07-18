package config

import "testing"

func TestLogLevelDefaultAndValidate(t *testing.T) {
	if got := Default().LogLevel(); got != "warn" {
		t.Errorf("default LogLevel = %q, want warn", got)
	}
	// A sparse config with no log section defaults to warn.
	c, err := Parse([]byte("proxy: {address: 10.0.0.1, port: 1080}\nmode: allowlist\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.LogLevel() != "warn" {
		t.Errorf("sparse LogLevel = %q, want warn", c.LogLevel())
	}
	// A valid explicit level survives parsing.
	c2, err := Parse([]byte("proxy: {address: 10.0.0.1, port: 1080}\nmode: allowlist\nlog: {level: debug}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c2.LogLevel() != "debug" {
		t.Errorf("explicit LogLevel = %q, want debug", c2.LogLevel())
	}
	// An unknown level is rejected.
	if _, err := Parse([]byte("proxy: {address: 10.0.0.1, port: 1080}\nmode: allowlist\nlog: {level: shout}\n")); err == nil {
		t.Error("expected invalid log.level to be rejected")
	}
}

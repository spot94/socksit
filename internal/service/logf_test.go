//go:build windows

package service

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// TestLogfFormat pins the single parseable shape of a service log line:
// "YYYY-MM-DD HH:MM:SS LEVEL message", with the level padded so messages align.
func TestLogfFormat(t *testing.T) {
	var buf bytes.Buffer
	r := &Runtime{log: &buf}
	r.logf("INFO", "hello %d", 5)
	r.logf("ERROR", "boom")

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), buf.String())
	}
	ts := `\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`
	if !regexp.MustCompile(`^` + ts + ` INFO  hello 5$`).MatchString(lines[0]) {
		t.Errorf("INFO line = %q", lines[0])
	}
	if !regexp.MustCompile(`^` + ts + ` ERROR boom$`).MatchString(lines[1]) {
		t.Errorf("ERROR line = %q", lines[1])
	}
}

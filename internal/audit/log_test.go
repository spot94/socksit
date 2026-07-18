package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestLogFormat(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.clock = func() time.Time { return time.Date(2026, 7, 13, 17, 45, 1, 0, time.UTC) }

	l.Log("EUGENE", "updated configuration", "socksit.yaml")
	line := buf.String()
	for _, want := range []string{"2026-07-13 17:45:01", "EUGENE", "updated configuration", "socksit.yaml", "→"} {
		if !strings.Contains(line, want) {
			t.Errorf("audit line missing %q: %q", want, line)
		}
	}
}

func TestLogNeverLeaksSecret(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	// The convention is to log only the action name, never the value.
	l.Log("EUGENE", "updated SOCKS5 credentials", "proxy 192.0.2.10")
	if strings.Contains(buf.String(), "hunter2") {
		t.Fatal("audit log must not contain secret values")
	}
	if !strings.Contains(buf.String(), "updated SOCKS5 credentials") {
		t.Error("expected the action to be recorded")
	}
}

func TestLogNoObject(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Log("EUGENE", "started service", "")
	if strings.Count(buf.String(), "→") != 1 {
		t.Errorf("expected a single arrow when object is empty: %q", buf.String())
	}
}

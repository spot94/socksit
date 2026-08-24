//go:build windows

package service

import (
	"bytes"
	"strings"
	"testing"
)

// A real line from the field: the engine only reports tunnel-internal addresses,
// so on its own it cannot say which application dropped the connection.
const engineErrLine = "+0300 2026-08-24 05:56:26 ERROR [3118060526 4m58s] connection: connection upload closed: " +
	"raw-read tcp4 172.19.0.1:65382->172.19.0.2:10419: An existing connection was forcibly closed by the remote host.\n"

func TestEngineLogAnnotatesOwningApp(t *testing.T) {
	var out bytes.Buffer
	a := newEngineLogAnnotator(&out, "") // no Clash API: nothing to look up
	a.ports["65382"] = "claude.exe"      // pretend the sampler saw this connection

	if _, err := a.Write([]byte(engineErrLine)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "[app: claude.exe]") {
		t.Errorf("expected the owning app to be named, got:\n%s", got)
	}
	if !strings.Contains(got, "raw-read tcp4 172.19.0.1:65382") {
		t.Errorf("the original line must be preserved, got:\n%s", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Error("the line must stay newline-terminated")
	}
}

func TestEngineLogPassesThroughAndSplits(t *testing.T) {
	var out bytes.Buffer
	a := newEngineLogAnnotator(&out, "")

	// Unrelated engine output is untouched.
	a.Write([]byte("+0300 INFO router: loaded rule-set\n"))
	if out.String() != "+0300 INFO router: loaded rule-set\n" {
		t.Errorf("unrelated output must pass through verbatim, got %q", out.String())
	}

	// A line split across writes is emitted once, whole.
	out.Reset()
	a.Write([]byte("+0300 ERROR partial 172.19.0.1:1"))
	if out.Len() != 0 {
		t.Errorf("an unterminated line must be held back, got %q", out.String())
	}
	a.Write([]byte("234: boom\n"))
	if got := out.String(); got != "+0300 ERROR partial 172.19.0.1:1234: boom\n" {
		t.Errorf("split line reassembled wrong: %q", got)
	}

	// An unknown port is left alone rather than mislabelled.
	out.Reset()
	a.Write([]byte(engineErrLine))
	if strings.Contains(out.String(), "[app:") {
		t.Errorf("an unmapped port must not be annotated, got %q", out.String())
	}
}

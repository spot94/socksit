//go:build windows

package service

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCopyFileNeverTruncatesItself reproduces the re-install bug: staging the
// engine copied C:\Program Files\SocksIt\sing-box.exe onto itself, and os.Create
// truncated it before it was read — leaving a 0-byte file that Windows rejects
// with "not a valid Win32 application".
func TestCopyFileNeverTruncatesItself(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sing-box.exe")
	want := []byte("MZ engine payload")
	if err := os.WriteFile(p, want, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := copyFile(p, p); err != nil {
		t.Fatalf("self-copy must be a no-op, got %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("file was truncated to %d bytes (was %d)", len(got), len(want))
	}

	// Same file reached through a differently-spelled path must be caught too.
	alt := filepath.Join(dir, ".", "sing-box.exe")
	if err := copyFile(alt, p); err != nil {
		t.Errorf("self-copy via an equivalent path must be a no-op, got %v", err)
	}
	if got, _ := os.ReadFile(p); len(got) != len(want) {
		t.Errorf("file truncated via an equivalent path: %d bytes", len(got))
	}
}

// TestCopyFileReplacesAtomically: a normal copy overwrites the destination, and a
// failed copy leaves the previous destination intact rather than truncated.
func TestCopyFileReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "new.exe")
	dst := filepath.Join(dir, "installed.exe")
	if err := os.WriteFile(src, []byte("new payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "new payload" {
		t.Errorf("dst = %q, want the new payload", got)
	}

	// Missing source: the destination must survive untouched.
	if err := copyFile(filepath.Join(dir, "absent.exe"), dst); err == nil {
		t.Error("copying a missing source must fail")
	}
	if got, _ := os.ReadFile(dst); string(got) != "new payload" {
		t.Errorf("dst damaged by a failed copy: %q", got)
	}
	// No staging leftovers.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if len(e.Name()) > 9 && e.Name()[:9] == ".socksit-" {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}

// TestLocateEngineIgnoresEmpty: an engine already truncated by the old bug must
// count as missing so the install re-downloads it instead of "copying" it.
func TestLocateEngineIgnoresEmpty(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "socksit.exe")
	engine := filepath.Join(dir, "sing-box.exe")
	if err := os.WriteFile(engine, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := locateEngine(exe); got != "" {
		t.Errorf("a 0-byte engine must be ignored, got %q", got)
	}
	if err := os.WriteFile(engine, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := locateEngine(exe); got != engine {
		t.Errorf("locateEngine = %q, want %q", got, engine)
	}
}

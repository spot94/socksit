//go:build windows

package service

import (
	"os"
	"path/filepath"
	"testing"
)

// freshBackupPath reuses <target>.old when it is absent or removable, so the swap
// does a plain (non-replacing) move.
func TestFreshBackupPathReusesOldWhenFree(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "socksit.exe")
	if got := freshBackupPath(target); got != target+".old" {
		t.Fatalf("expected %q when no .old exists, got %q", target+".old", got)
	}
	// An existing but removable .old is cleared and reused.
	if err := os.WriteFile(target+".old", []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := freshBackupPath(target); got != target+".old" {
		t.Fatalf("expected reuse of %q, got %q", target+".old", got)
	}
	if _, err := os.Stat(target + ".old"); !os.IsNotExist(err) {
		t.Fatalf("stale .old should have been removed, stat err=%v", err)
	}
}

// renameWithRetry moves a file that isn't locked on the first try.
func TestRenameWithRetry(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "a.exe")
	to := filepath.Join(dir, "a.exe.old")
	if err := os.WriteFile(from, []byte("bin"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := renameWithRetry(from, to); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := os.Stat(to); err != nil {
		t.Fatalf("destination missing after rename: %v", err)
	}
	if _, err := os.Stat(from); !os.IsNotExist(err) {
		t.Fatalf("source should be gone after rename, stat err=%v", err)
	}
}

package logfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStripANSI(t *testing.T) {
	in := "\x1b[31mERROR\x1b[0m [\x1b[38;5;83m1462226499\x1b[0m] boom"
	got := string(StripANSI([]byte(in)))
	if want := "ERROR [1462226499] boom"; got != want {
		t.Errorf("StripANSI = %q, want %q", got, want)
	}
}

func TestTailLastN(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.log")
	var b strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, "line-%d\n", i)
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err := Tail(p, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 5 || lines[0] != "line-95" || lines[4] != "line-99" {
		t.Errorf("Tail(5) = %v", lines)
	}
	// Asking for more lines than exist returns them all, no empty trailer.
	all, _ := Tail(p, 1000)
	if len(all) != 100 || all[99] != "line-99" {
		t.Errorf("Tail(1000) len=%d last=%q", len(all), all[len(all)-1])
	}
}

func TestTailStripsANSI(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.log")
	os.WriteFile(p, []byte("\x1b[31mred\x1b[0m\nplain\n"), 0o600)
	lines, err := Tail(p, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0] != "red" || lines[1] != "plain" {
		t.Errorf("Tail strip = %v", lines)
	}
}

func TestRotatorRotatesAndKeepsBackups(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.log")
	// 100-byte segments, keep 2 backups.
	r, err := NewRotator(p, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	// Each write is ~20 bytes; 30 writes forces several rotations.
	for i := 0; i < 30; i++ {
		if _, err := r.Write([]byte(fmt.Sprintf("payload-line-%03d\n", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	// Base file exists and is under the threshold.
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("base log missing: %v", err)
	}
	if fi.Size() > 100 {
		t.Errorf("base segment not rotated: %d bytes", fi.Size())
	}
	// Exactly maxBackups backups exist; no name.3.
	if _, err := os.Stat(p + ".1"); err != nil {
		t.Errorf("expected %s.1: %v", p, err)
	}
	if _, err := os.Stat(p + ".2"); err != nil {
		t.Errorf("expected %s.2: %v", p, err)
	}
	if _, err := os.Stat(p + ".3"); err == nil {
		t.Errorf("did not expect %s.3 (maxBackups=2)", p)
	}
}

func TestRotatorReopenKeepsAppending(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.log")
	r, _ := NewRotator(p, 1<<20, 3)
	r.Write([]byte("first\n"))
	r.Close()
	// Reopen: size is read from disk so we keep appending, not truncate.
	r2, _ := NewRotator(p, 1<<20, 3)
	r2.Write([]byte("second\n"))
	r2.Close()
	b, _ := os.ReadFile(p)
	if got := string(b); got != "first\nsecond\n" {
		t.Errorf("append across reopen = %q", got)
	}
}

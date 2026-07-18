// Package logfile provides size-rotated append log files plus tail/ANSI helpers,
// shared by the service (which writes socksit.log and audit.log) and the panel +
// CLI (which read the tail for display). Keeping both sides here means the write
// format and the read/cleanup logic can't drift apart.
package logfile

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
)

// DefaultMaxSize is the rotation threshold used when a non-positive size is passed.
const DefaultMaxSize = 10 << 20 // 10 MiB

// Rotator is an append writer that rotates its file once it would exceed
// MaxSize, keeping up to MaxBackups numbered backups (name.1 is the most recent
// rotation, name.MaxBackups the oldest). It is safe for concurrent use — which
// also serialises the multiple goroutines that write the runtime log. Rotation
// renames on disk and reopens the base name, so a reader tailing `name` always
// sees the current segment.
type Rotator struct {
	path       string
	maxSize    int64
	maxBackups int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// NewRotator opens (creating/appending) path. maxSize is in bytes (<=0 uses
// DefaultMaxSize); maxBackups <0 is treated as 0 (rotate by truncation).
func NewRotator(path string, maxSize int64, maxBackups int) (*Rotator, error) {
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}
	if maxBackups < 0 {
		maxBackups = 0
	}
	r := &Rotator{path: path, maxSize: maxSize, maxBackups: maxBackups}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Rotator) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	var sz int64
	if fi, err := f.Stat(); err == nil {
		sz = fi.Size()
	}
	r.f, r.size = f, sz
	return nil
}

// Write appends p, rotating first if the file already has content and adding p
// would push it past maxSize. It never returns an error to the caller (a dead
// sink must not block the service's other log writers), matching the runtime's
// safeMulti contract.
func (r *Rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return len(p), nil // closed or rotation gave up — swallow
	}
	if r.size > 0 && r.size+int64(len(p)) > r.maxSize {
		r.rotate() // best effort; on failure keep appending to the current file
	}
	if r.f == nil {
		return len(p), nil
	}
	n, _ := r.f.Write(p)
	r.size += int64(n)
	return len(p), nil
}

// rotate closes the current file, shifts backups up by one (dropping the
// oldest), renames name -> name.1, and reopens a fresh name. On Windows a file
// must be closed before it can be renamed, which the close-first order ensures.
func (r *Rotator) rotate() {
	_ = r.f.Close()
	r.f = nil
	if r.maxBackups <= 0 {
		// No history wanted: start the base file over.
		if f, err := os.OpenFile(r.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600); err == nil {
			r.f, r.size = f, 0
		}
		return
	}
	_ = os.Remove(r.backupName(r.maxBackups)) // drop the oldest
	for i := r.maxBackups - 1; i >= 1; i-- {
		_ = os.Rename(r.backupName(i), r.backupName(i+1))
	}
	_ = os.Rename(r.path, r.backupName(1))
	_ = r.open() // reopen a fresh base name; on failure r.f stays nil (Write swallows)
}

func (r *Rotator) backupName(i int) string { return fmt.Sprintf("%s.%d", r.path, i) }

// Close closes the underlying file.
func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

// StripANSI removes ANSI SGR (colour) escape sequences — the sing-box engine
// writes coloured output even to a non-terminal, which would otherwise litter
// the file and the panel/CLI views with raw escape codes.
func StripANSI(b []byte) []byte { return ansiRE.ReplaceAll(b, nil) }

// Tail returns up to the last n lines of the file at path with ANSI escapes
// stripped. It reads from the end in chunks, so it stays cheap regardless of how
// large the log has grown.
func Tail(path string, n int) ([]string, error) {
	if n <= 0 {
		n = 200
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	const chunk = 64 << 10
	var (
		buf []byte
		off = fi.Size()
	)
	for off > 0 && bytes.Count(buf, []byte{'\n'}) <= n {
		read := int64(chunk)
		if read > off {
			read = off
		}
		off -= read
		tmp := make([]byte, read)
		if _, err := f.ReadAt(tmp, off); err != nil && err != io.EOF {
			return nil, err
		}
		buf = append(tmp, buf...)
	}

	text := strings.ReplaceAll(string(StripANSI(buf)), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1] // drop the empty tail from a trailing newline
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

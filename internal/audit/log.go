// Package audit writes a human-readable local action log covering the user's
// administrative operations (config changes, mode toggles, start/stop) — the
// SocksIt adaptation of the corporate SEC-3 requirement. Lines read
// "<time>  <actor> → <action> → <object>". Secrets are never logged.
package audit

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// Logger appends audit lines to an underlying writer, safe for concurrent use.
type Logger struct {
	mu    sync.Mutex
	w     io.Writer
	clock func() time.Time
}

// New returns a Logger writing to w.
func New(w io.Writer) *Logger {
	return &Logger{w: w, clock: time.Now}
}

// Log records that actor performed action on object. object should be a
// human-readable name; include any id in parentheses at the call site.
func (l *Logger) Log(actor, action, object string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.clock().Format("2006-01-02 15:04:05")
	if object == "" {
		fmt.Fprintf(l.w, "%s  %s → %s\n", ts, actor, action)
		return
	}
	fmt.Fprintf(l.w, "%s  %s → %s → %s\n", ts, actor, action, object)
}

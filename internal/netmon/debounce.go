// Package netmon watches Windows network-change events and, after coalescing
// the burst a single transition produces, triggers the supervisor to heal
// (re-assert routes / restart the engine). See plan U6/KTD8.
package netmon

import (
	"sync"
	"time"
)

// Debouncer coalesces rapid Signal() calls: fn runs once, quiet after the last
// signal. This is the "forward-to-channel, do real work later" pattern — network
// transitions fire bursts of callbacks and we want a single heal.
type Debouncer struct {
	d     time.Duration
	fn    func()
	mu    sync.Mutex
	timer *time.Timer
	stop  bool
}

// NewDebouncer returns a debouncer that runs fn quiet-period d after the last
// Signal().
func NewDebouncer(d time.Duration, fn func()) *Debouncer {
	return &Debouncer{d: d, fn: fn}
}

// Signal registers an event, (re)starting the quiet timer.
func (b *Debouncer) Signal() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stop {
		return
	}
	if b.timer != nil {
		b.timer.Stop()
	}
	b.timer = time.AfterFunc(b.d, b.fn)
}

// Stop cancels any pending fire and prevents future ones.
func (b *Debouncer) Stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stop = true
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
}

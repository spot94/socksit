package config

import (
	"context"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watch invokes onChange (debounced by debounce) whenever the file at path is
// modified, until ctx is cancelled. It watches the parent directory because
// editors frequently replace files rather than writing in place, and coalesces
// the burst of events a single save produces.
func Watch(ctx context.Context, path string, debounce time.Duration, onChange func()) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := w.Add(dir); err != nil {
		w.Close()
		return err
	}
	target := filepath.Clean(path)
	go func() {
		defer w.Close()
		var timer *time.Timer
		for {
			select {
			case <-ctx.Done():
				if timer != nil {
					timer.Stop()
				}
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if filepath.Clean(ev.Name) != target {
					continue
				}
				if timer != nil {
					timer.Stop()
				}
				timer = time.AfterFunc(debounce, onChange)
			case _, ok := <-w.Errors:
				if !ok {
					return
				}
			}
		}
	}()
	return nil
}

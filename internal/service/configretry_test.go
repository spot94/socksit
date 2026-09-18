//go:build windows

package service

import (
	"testing"
	"time"
)

// A machine installed with a bad feed URL, or while the config server is down,
// used to sit unconfigured for the whole interval. With a bootstrap preset that
// means an hour with nothing proxied and no error anywhere the user looks.
func TestNextFetchDelay(t *testing.T) {
	const hour = time.Hour

	t.Run("success waits the configured interval", func(t *testing.T) {
		if got := nextFetchDelay(hour, 0); got != hour {
			t.Errorf("got %s, want %s", got, hour)
		}
	})

	t.Run("failures back off from a minute and stop at the interval", func(t *testing.T) {
		want := []time.Duration{
			time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute,
			16 * time.Minute, 32 * time.Minute, hour, hour, hour,
		}
		for i, w := range want {
			if got := nextFetchDelay(hour, i+1); got != w {
				t.Errorf("after %d failures got %s, want %s", i+1, got, w)
			}
		}
	})

	// ConfigEvery floors at a minute, so this is the tightest schedule possible:
	// the retry must not turn out longer than the normal interval.
	t.Run("a one-minute interval never backs off past itself", func(t *testing.T) {
		for _, fails := range []int{1, 2, 10, 1000} {
			if got := nextFetchDelay(time.Minute, fails); got != time.Minute {
				t.Errorf("after %d failures got %s, want 1m", fails, got)
			}
		}
	})

	// The doubling loop must not spin or overflow on an absurd failure count.
	t.Run("a huge failure count terminates at the cap", func(t *testing.T) {
		done := make(chan time.Duration, 1)
		go func() { done <- nextFetchDelay(hour, 1<<20) }()
		select {
		case got := <-done:
			if got != hour {
				t.Errorf("got %s, want %s", got, hour)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("nextFetchDelay did not return")
		}
	})
}

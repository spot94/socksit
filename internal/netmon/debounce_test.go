package netmon

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestDebouncerCoalesces(t *testing.T) {
	var calls atomic.Int32
	b := NewDebouncer(60*time.Millisecond, func() { calls.Add(1) })

	// A burst of 5 rapid signals should coalesce into a single fire.
	for i := 0; i < 5; i++ {
		b.Signal()
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Errorf("expected 1 coalesced fire, got %d", got)
	}

	// A second, separated burst fires again.
	b.Signal()
	time.Sleep(150 * time.Millisecond)
	if got := calls.Load(); got != 2 {
		t.Errorf("expected 2 total fires, got %d", got)
	}
}

func TestDebouncerStop(t *testing.T) {
	var calls atomic.Int32
	b := NewDebouncer(40*time.Millisecond, func() { calls.Add(1) })
	b.Signal()
	b.Stop()
	time.Sleep(120 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Errorf("Stop should cancel the pending fire, got %d", got)
	}
	b.Signal() // no-op after Stop
	time.Sleep(120 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Errorf("Signal after Stop must not fire, got %d", got)
	}
}

//go:build windows

package netstate

import "testing"

func TestStaleAdapterAbsentOnCleanMachine(t *testing.T) {
	present, err := StaleAdapterPresent()
	if err != nil {
		t.Fatalf("StaleAdapterPresent: %v", err)
	}
	if present {
		t.Skip("a 'socksit' adapter exists on this machine (prior run?) — skipping clean-state assertion")
	}
}

func TestReconcileReportsClean(t *testing.T) {
	present, _ := StaleAdapterPresent()
	needs, detail, err := Reconcile()
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if needs != present {
		t.Errorf("Reconcile needsRepair=%v but StaleAdapterPresent=%v", needs, present)
	}
	if !present && detail != "clean" {
		t.Errorf("expected 'clean' detail on a clean machine, got %q", detail)
	}
}

//go:build windows

// Package netstate owns the reversible network mutations (TUN adapter + routes)
// so cleanup never depends on the engine living long enough to clean up after
// itself (plan U6/KTD6). On startup it reconciles state left by a prior hard
// kill; on shutdown the supervisor reverts what it changed.
package netstate

import (
	"fmt"
	"net"
	"strings"

	"socksit/internal/singbox"
)

// StaleAdapterPresent reports whether a leftover SocksIt Wintun adapter exists
// from a previous crash. Non-privileged: it enumerates interfaces by name.
func StaleAdapterPresent() (bool, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, fmt.Errorf("enumerate interfaces: %w", err)
	}
	for _, ifc := range ifaces {
		if strings.EqualFold(ifc.Name, singbox.AdapterName) {
			return true, nil
		}
	}
	return false, nil
}

// Reconcile performs idempotent startup reconciliation. Detection is
// non-privileged; removing a stale adapter and restoring routes is performed at
// runtime by the LocalSystem service via the Wintun API (adapter lifecycle is
// owned by the supervisor). This function reports what needs repair so the
// service can act and log it.
//
// TODO(runtime): wire adapter removal through the Wintun API
// (wintun.dll: WintunOpenAdapter by name -> WintunCloseAdapter/DeleteDriver) and
// route restoration from the pre-run snapshot. Requires SYSTEM + admin, so it is
// not exercised in unit tests.
func Reconcile() (needsRepair bool, detail string, err error) {
	stale, err := StaleAdapterPresent()
	if err != nil {
		return false, "", err
	}
	if stale {
		return true, fmt.Sprintf("stale %q adapter present from a prior run", singbox.AdapterName), nil
	}
	return false, "clean", nil
}

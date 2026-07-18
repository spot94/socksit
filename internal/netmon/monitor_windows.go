//go:build windows

package netmon

import (
	"time"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type unregisterer interface{ Unregister() error }

// Monitor subscribes to Windows interface / unicast-address / route change
// events. Each OS callback does only a non-blocking Signal() (KTD8); the
// debouncer coalesces the burst and runs onChange once the network settles.
type Monitor struct {
	deb *Debouncer
	cbs []unregisterer
}

// Start registers the change callbacks. debounce is the quiet window before a
// heal fires (e.g. 2s).
func Start(debounce time.Duration, onChange func()) (*Monitor, error) {
	m := &Monitor{deb: NewDebouncer(debounce, onChange)}

	ic, err := winipcfg.RegisterInterfaceChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPInterfaceRow) {
		m.deb.Signal()
	})
	if err != nil {
		return nil, err
	}
	m.cbs = append(m.cbs, ic)

	uc, err := winipcfg.RegisterUnicastAddressChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibUnicastIPAddressRow) {
		m.deb.Signal()
	})
	if err != nil {
		m.Stop()
		return nil, err
	}
	m.cbs = append(m.cbs, uc)

	rc, err := winipcfg.RegisterRouteChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPforwardRow2) {
		m.deb.Signal()
	})
	if err != nil {
		m.Stop()
		return nil, err
	}
	m.cbs = append(m.cbs, rc)

	return m, nil
}

// Stop unregisters all callbacks and cancels any pending heal. Call from a
// normal goroutine, never from inside a callback.
func (m *Monitor) Stop() {
	for _, cb := range m.cbs {
		_ = cb.Unregister()
	}
	m.cbs = nil
	m.deb.Stop()
}

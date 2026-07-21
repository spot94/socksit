//go:build windows

package tray

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// notifyIconData mirrors NOTIFYICONDATAW. The layout is copied verbatim from
// fyne.io/systray (systray_windows.go) so it matches the icon this process
// already owns.
type notifyIconData struct {
	Size                       uint32
	Wnd                        windows.Handle
	ID, Flags, CallbackMessage uint32
	Icon                       windows.Handle
	Tip                        [128]uint16
	State, StateMask           uint32
	Info                       [256]uint16
	Timeout, Version           uint32
	InfoTitle                  [64]uint16
	InfoFlags                  uint32
	GuidItem                   windows.GUID
	BalloonIcon                windows.Handle
}

var (
	shell32b         = windows.NewLazySystemDLL("shell32.dll")
	pShellNotifyIcon = shell32b.NewProc("Shell_NotifyIconW")
	user32b          = windows.NewLazySystemDLL("user32.dll")
	pFindWindow      = user32b.NewProc("FindWindowW")
	balloonMu        sync.Mutex
)

// showBalloon shows a notification-area balloon (a toast on Win10/11) on the tray
// icon this process already owns via fyne.io/systray — window class "SystrayClass",
// icon id 100. Reusing that icon avoids a second tray icon and a second message
// loop. Best effort: any failure is ignored (the tray menu item + tooltip remain
// as the reliable surface), so callers never depend on it.
func showBalloon(title, body string) {
	balloonMu.Lock()
	defer balloonMu.Unlock()

	const (
		nimModify = 0x00000001
		nifInfo   = 0x00000010
		niifInfo  = 0x00000001
		systrayID = 100 // fyne.io/systray's icon uID
	)
	cls, err := windows.UTF16PtrFromString("SystrayClass")
	if err != nil {
		return
	}
	hwnd, _, _ := pFindWindow.Call(uintptr(unsafe.Pointer(cls)), 0)
	if hwnd == 0 {
		return // systray window not found — degrade silently
	}
	nid := notifyIconData{
		Wnd:       windows.Handle(hwnd),
		ID:        systrayID,
		Flags:     nifInfo,
		InfoFlags: niifInfo,
	}
	nid.Size = uint32(unsafe.Sizeof(nid))
	putUTF16(nid.InfoTitle[:], title)
	putUTF16(nid.Info[:], body)
	_, _, _ = pShellNotifyIcon.Call(uintptr(nimModify), uintptr(unsafe.Pointer(&nid)))
}

// putUTF16 writes s into dst as a NUL-terminated UTF-16 string, truncating to fit.
func putUTF16(dst []uint16, s string) {
	u, err := windows.UTF16FromString(s)
	if err != nil {
		return
	}
	if len(u) > len(dst) {
		u = u[:len(dst)]
	}
	copy(dst, u)
	dst[len(dst)-1] = 0 // ensure termination even if truncated
}

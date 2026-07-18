//go:build windows

package panel

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// openFileName mirrors the Win32 OPENFILENAMEW struct (64-bit layout). Pointers
// and handles are uintptr so Go's alignment matches the C struct; lStructSize is
// taken from unsafe.Sizeof so the two always agree.
type openFileName struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        uintptr
	dwReserved        uint32
	flagsEx           uint32
}

const (
	ofnExplorer      = 0x00080000
	ofnFileMustExist = 0x00001000
	ofnPathMustExist = 0x00000800
	ofnNoChangeDir   = 0x00000008
)

var (
	comdlg32            = windows.NewLazySystemDLL("comdlg32.dll")
	procGetOpenFileName = comdlg32.NewProc("GetOpenFileNameW")
)

// browseExe shows the standard "open file" dialog filtered to executables and
// returns the chosen full path, or "" if cancelled. owner is the panel HWND so
// the dialog is modal to the window.
func browseExe(owner uintptr) string {
	buf := make([]uint16, 1024)
	ofn := openFileName{
		hwndOwner:    owner,
		lpstrFilter:  utf16MultiSz("Executables (*.exe)\x00*.exe\x00All files (*.*)\x00*.*\x00"),
		lpstrFile:    &buf[0],
		nMaxFile:     uint32(len(buf)),
		nFilterIndex: 1,
		lpstrTitle:   utf16Ptr("Select an application (.exe)"),
		flags:        ofnExplorer | ofnFileMustExist | ofnPathMustExist | ofnNoChangeDir,
	}
	ofn.lStructSize = uint32(unsafe.Sizeof(ofn))
	r, _, _ := procGetOpenFileName.Call(uintptr(unsafe.Pointer(&ofn)))
	if r == 0 {
		return "" // cancelled or error
	}
	return windows.UTF16ToString(buf)
}

// utf16Ptr encodes a normal (NUL-free) string.
func utf16Ptr(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return nil
	}
	return p
}

// utf16MultiSz encodes a double-NUL-terminated filter string (which contains
// embedded NULs, so UTF16PtrFromString cannot be used). A final terminator is
// appended.
func utf16MultiSz(s string) *uint16 {
	r := []rune(s)
	u := make([]uint16, 0, len(r)+1)
	for _, c := range r {
		u = append(u, uint16(c))
	}
	u = append(u, 0) // final terminator after the last (already NUL-terminated) entry
	return &u[0]
}

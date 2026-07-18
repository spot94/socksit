//go:build windows

// Package panel is the single-window control panel, rendered with WebView2 (via
// the pure-Go github.com/jchv/go-webview2 — no cgo). The UI lives in embedded
// HTML/CSS/JS (web/index.html); the Go side exposes bindings (bindings_windows.go).
// Everything happens in one window: sidebar sections (Dashboard, Settings,
// Statistics, Logs, Diagnostics, About), light/dark themes, inline results — no
// extra windows, dialogs, or notifications.
//
// WebView2 invokes bound Go functions synchronously on the UI thread, so any slow
// operation (proxy test, service start/stop, diagnostics) runs on a goroutine and
// delivers its result back to JS via window.__result(id, payload) — see the
// start* bindings. Fast calls (state, config, logs) return directly.
package panel

import (
	_ "embed"
	"encoding/json"
	"errors"
	"runtime"
	"time"
	"unsafe"

	webview "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	callTimeout = 3 * time.Second
	windowTitle = "SocksIt — Control Panel"
	// panelMutexName guards a single panel window per machine.
	panelMutexName = `Global\SocksItPanel`
)

//go:embed web/index.html
var indexHTML string

// panelMutex keeps the singleton handle alive for the process lifetime.
var panelMutex windows.Handle

// Run opens the control panel window and blocks until it is closed. section is
// the initial sidebar section ("dashboard", "settings", "logs", …). If a panel is
// already open, this focuses it and returns.
func Run(pipe, configPath, dataDir, version, section string) error {
	if !acquireSingleton() {
		focusExisting()
		return nil
	}
	// WebView2/COM require the message loop on a locked OS (STA) thread.
	runtime.LockOSThread()

	w := webview.NewWithOptions(webview.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview.WindowOptions{
			Title:  windowTitle,
			Width:  1060,
			Height: 720,
			Center: true,
		},
	})
	if w == nil {
		msg := "SocksIt could not open its window.\n\n" +
			"This needs the Microsoft Edge WebView2 Runtime, which ships with Windows 10/11. " +
			"If it is missing, install \"Evergreen WebView2 Runtime\" from Microsoft, then start SocksIt again."
		messageBox("SocksIt", msg)
		return errors.New("WebView2 runtime unavailable")
	}
	defer w.Destroy()

	if section == "" {
		section = "dashboard"
	}
	a := &app{w: w, pipe: pipe, configPath: configPath, dataDir: dataDir, version: version}
	a.lang = a.getLang() // "" until the UI syncs via appSetLang on boot
	a.bind()
	// Init scripts run before the page loads (Bind also injected its stubs here).
	w.Init("window.__initialSection=" + jsStr(section) + ";")
	setWindowIcon(w)
	// Paint the native frame to match the saved theme before the page shows,
	// avoiding a light-title-bar flash. JS re-affirms it on load / theme change.
	dark := false
	switch a.getTheme() {
	case "dark":
		dark = true
	case "light":
		dark = false
	default:
		dark = systemUsesDark()
	}
	applyDarkTitleBar(uintptr(w.Window()), dark)
	w.SetHtml(indexHTML)
	w.Run()
	return nil
}

// acquireSingleton returns true if this is the only panel; it holds the mutex for
// the process lifetime.
func acquireSingleton() bool {
	name, err := windows.UTF16PtrFromString(panelMutexName)
	if err != nil {
		return true
	}
	h, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return false
	}
	if err != nil {
		return true
	}
	panelMutex = h
	return true
}

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	procFindWindow   = user32.NewProc("FindWindowW")
	procSetForeg     = user32.NewProc("SetForegroundWindow")
	procShowWindow   = user32.NewProc("ShowWindow")
	procSendMessage  = user32.NewProc("SendMessageW")
	procSetWindowPos = user32.NewProc("SetWindowPos")

	dwmapi                    = windows.NewLazySystemDLL("dwmapi.dll")
	procDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")
)

// DWMWA_USE_IMMERSIVE_DARK_MODE: 20 on Windows 10 2004+/11, 19 on 1809–1909.
const (
	dwmwaDarkMode    = 20
	dwmwaDarkModeOld = 19
)

// applyDarkTitleBar paints the native window frame/title bar dark or light so it
// matches the in-page theme (the WebView2 window is native — CSS cannot style it).
func applyDarkTitleBar(hwnd uintptr, dark bool) {
	if hwnd == 0 {
		return
	}
	var b int32
	if dark {
		b = 1
	}
	r, _, _ := procDwmSetWindowAttribute.Call(hwnd, dwmwaDarkMode, uintptr(unsafe.Pointer(&b)), 4)
	if r != 0 { // older Windows 10 build uses attribute 19
		_, _, _ = procDwmSetWindowAttribute.Call(hwnd, dwmwaDarkModeOld, uintptr(unsafe.Pointer(&b)), 4)
	}
	// Nudge the non-client area to repaint immediately.
	const swpFrameChanged, swpNoMove, swpNoSize, swpNoZOrder = 0x0020, 0x0002, 0x0001, 0x0004
	_, _, _ = procSetWindowPos.Call(hwnd, 0, 0, 0, 0, 0, swpFrameChanged|swpNoMove|swpNoSize|swpNoZOrder)
}

// systemUsesDark reports whether the Windows app theme is dark (used to resolve
// the "system" preference for the initial title-bar colour).
func systemUsesDark() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("AppsUseLightTheme")
	if err != nil {
		return false
	}
	return v == 0
}

// focusExisting brings an already-open panel window to the foreground.
func focusExisting() {
	title, err := windows.UTF16PtrFromString(windowTitle)
	if err != nil {
		return
	}
	hwnd, _, _ := procFindWindow.Call(0, uintptr(unsafe.Pointer(title)))
	if hwnd == 0 {
		return
	}
	const swRestore = 9
	_, _, _ = procShowWindow.Call(hwnd, swRestore)
	_, _, _ = procSetForeg.Call(hwnd)
}

// setWindowIcon applies the exe's own icon to the panel window (best-effort).
func setWindowIcon(w webview.WebView) {
	hwnd := w.Window()
	if hwnd == nil {
		return
	}
	exe, err := windows.UTF16PtrFromString(executablePath())
	if err != nil {
		return
	}
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	extractIcon := shell32.NewProc("ExtractIconW")
	hIcon, _, _ := extractIcon.Call(0, uintptr(unsafe.Pointer(exe)), 0)
	if hIcon == 0 || hIcon == 1 {
		return
	}
	const wmSetIcon = 0x0080
	_, _, _ = procSendMessage.Call(uintptr(hwnd), wmSetIcon, 0 /*ICON_SMALL*/, hIcon)
	_, _, _ = procSendMessage.Call(uintptr(hwnd), wmSetIcon, 1 /*ICON_BIG*/, hIcon)
}

// jsStr encodes a Go string as a JS/JSON string literal.
func jsStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// messageBox shows a native OK dialog. Used only for a fatal startup failure
// (e.g. the WebView2 runtime is missing) so a GUI-subsystem launch is not silent.
func messageBox(title, text string) {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString(title)
	proc := user32.NewProc("MessageBoxW")
	const mbIconError = 0x10
	_, _, _ = proc.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), mbIconError)
}

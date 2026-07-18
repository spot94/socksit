//go:build windows

package panel

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	webview "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
	"gopkg.in/yaml.v3"

	"socksit/internal/config"
	"socksit/internal/ipc"
	"socksit/internal/proc"
	"socksit/internal/proxytest"
	"socksit/internal/service"
)

// app holds the panel's runtime dependencies and the webview handle.
type app struct {
	w          webview.WebView
	pipe       string
	configPath string
	dataDir    string
	version    string
	lang       string // "" | "en" | "ru" — for localizing backend-produced messages
}

// tr picks the string for the current language (only en/ru supported).
func (a *app) tr(en, ru string) string {
	if a.lang == "ru" {
		return ru
	}
	return en
}

// ---- data shapes exchanged with the frontend (JSON) ----

type stateView struct {
	Installed  bool   `json:"installed"`
	Running    bool   `json:"running"`
	Elevated   bool   `json:"elevated"`
	Enabled    bool   `json:"enabled"`
	Engine     string `json:"engine"` // up | down | paused | <raw state>
	PID        int    `json:"pid"`
	Proxy      string `json:"proxy"`
	Apps       int    `json:"apps"`
	Mode       string `json:"mode"`
	KillSwitch bool   `json:"killSwitch"`
	ShowTray   bool   `json:"showTray"`
	Version    string `json:"version"`
	StatusText string `json:"statusText"`
}

type configView struct {
	Address          string   `json:"address"`
	Port             int      `json:"port"`
	Mode             string   `json:"mode"`
	KillSwitch       bool     `json:"killSwitch"`
	ShowTray         bool     `json:"showTray"`
	UDP              bool     `json:"udp"`
	DirectSubnets    []string `json:"directSubnets"`
	Apps             []string `json:"apps"`
	CfgURL           string   `json:"cfgUrl"`
	CfgInterval      string   `json:"cfgInterval"`
	CfgSigned        bool     `json:"cfgSigned"`
	CfgPubKey        string   `json:"cfgPubKey"`
	CfgMerge         string   `json:"cfgMerge"`
	CfgProxy         string   `json:"cfgProxy"`
	CfgPendingPubKey string   `json:"cfgPendingPubKey"`
	ManagedApps      []string `json:"managedApps"`
	ManagedSubnets   []string `json:"managedSubnets"`
	CfgLocked        []string `json:"cfgLocked"`
}

type saveInput struct {
	Address       string   `json:"address"`
	Port          int      `json:"port"`
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	Mode          string   `json:"mode"`
	KillSwitch    bool     `json:"killSwitch"`
	ShowTray      bool     `json:"showTray"`
	UDP           bool     `json:"udp"`
	DirectSubnets []string `json:"directSubnets"`
	Apps          []string `json:"apps"`
	CfgURL        string   `json:"cfgUrl"`
	CfgInterval   string   `json:"cfgInterval"`
	CfgSigned     bool     `json:"cfgSigned"`
	CfgPubKey     string   `json:"cfgPubKey"`
	CfgMerge      string   `json:"cfgMerge"`
	CfgProxy      string   `json:"cfgProxy"`
}

type result struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type statRow struct {
	Process     string `json:"process"`
	Destination string `json:"destination"`
	Net         string `json:"net"`
	Via         string `json:"via"`
	Up          string `json:"up"`
	Down        string `json:"down"`
	UpBytes     int64  `json:"upB"`   // raw, for numeric sorting
	DownBytes   int64  `json:"downB"` // raw, for numeric sorting
}

type statsView struct {
	Rows   []statRow `json:"rows"`
	Totals string    `json:"totals"`
	Error  string    `json:"error"`
}

// ipcStatus mirrors the fields returned by the service Runtime.Status.
type ipcStatus struct {
	Enabled bool   `json:"enabled"`
	State   string `json:"state"`
	PID     int    `json:"pid"`
	Version string `json:"version"` // the running service's build version
}

func (a *app) bind() {
	// Fast (synchronous) calls: they return within milliseconds.
	_ = a.w.Bind("appState", a.state)
	_ = a.w.Bind("appGetConfig", a.getConfig)
	_ = a.w.Bind("appSaveConfig", a.saveConfig)
	_ = a.w.Bind("appToggle", a.toggleProxying)
	_ = a.w.Bind("appReload", a.reload)
	_ = a.w.Bind("appLogs", a.logs)
	_ = a.w.Bind("appProcesses", func() []string { return nonNil(proc.Names()) })
	_ = a.w.Bind("appBrowseExe", func() string { return browseExe(uintptr(a.w.Window())) })
	_ = a.w.Bind("appGetTheme", a.getTheme)
	_ = a.w.Bind("appSetTheme", a.setTheme)
	_ = a.w.Bind("appGetLang", a.getLang)
	_ = a.w.Bind("appSetLang", a.setLang)
	_ = a.w.Bind("appSetDark", func(dark bool) { applyDarkTitleBar(uintptr(a.w.Window()), dark) })
	_ = a.w.Bind("appElevate", a.elevate)
	_ = a.w.Bind("appRestartForUpdate", a.restartForUpdate)
	_ = a.w.Bind("appAcceptKeyRotation", a.acceptKeyRotation)
	_ = a.w.Bind("appDeclineKeyRotation", a.declineKeyRotation)
	_ = a.w.Bind("appGetUpdate", a.getUpdate)
	_ = a.w.Bind("appSaveUpdate", a.saveUpdate)
	_ = a.w.Bind("appUpdateStatus", a.updateStatus)
	// Slow calls: run off the UI thread and resolve via window.__result(id, …).
	_ = a.w.Bind("startServiceAction", a.startServiceAction)
	_ = a.w.Bind("startTestProxy", a.startTestProxy)
	_ = a.w.Bind("startDiagnostics", a.startDiagnostics)
	_ = a.w.Bind("startStats", a.startStats)
	_ = a.w.Bind("startUpdateCheck", a.startUpdateCheck)
	_ = a.w.Bind("startUpdateApply", a.startUpdateApply)
	_ = a.w.Bind("appConfigStatus", a.configStatus)
	_ = a.w.Bind("startConfigFetch", a.startConfigFetch)
}

// configStatus returns the managed-config feed status (raw JSON).
func (a *app) configStatus() json.RawMessage {
	if resp, err := ipc.Call(a.pipe, ipc.Request{Op: ipc.OpConfigStatus}, callTimeout); err == nil && resp.OK {
		return json.RawMessage(resp.Data)
	}
	b, _ := json.Marshal(map[string]any{"managed": false})
	return json.RawMessage(b)
}

// startConfigFetch pulls the managed config now (network, off the UI thread).
func (a *app) startConfigFetch(id string) {
	go func() {
		resp, err := ipc.Call(a.pipe, ipc.Request{Op: ipc.OpConfigFetch}, 40*time.Second)
		if err != nil || !resp.OK {
			a.resolve(id, map[string]any{"error": a.tr("the service is not reachable", "служба недоступна")})
			return
		}
		a.resolve(id, json.RawMessage(resp.Data))
	}()
}

type updateView struct {
	Endpoint      string `json:"endpoint"`
	Channel       string `json:"channel"`
	Mode          string `json:"mode"`
	CheckInterval string `json:"checkInterval"`
	Proxy         string `json:"proxy"`
	Version       string `json:"version"`
}

type updateInput struct {
	Endpoint      string `json:"endpoint"`
	Channel       string `json:"channel"`
	Mode          string `json:"mode"`
	CheckInterval string `json:"checkInterval"`
	Proxy         string `json:"proxy"`
}

func (a *app) getUpdate() updateView {
	c := a.loadConfig()
	return updateView{
		Endpoint:      c.Update.Endpoint,
		Channel:       c.Update.Channel,
		Mode:          c.Update.Mode,
		CheckInterval: c.Update.CheckInterval,
		Proxy:         c.Update.Proxy,
		Version:       a.version,
	}
}

func (a *app) saveUpdate(in updateInput) result {
	c := a.loadConfig()
	c.Update.Endpoint = strings.TrimSpace(in.Endpoint)
	if strings.TrimSpace(in.Channel) != "" {
		c.Update.Channel = strings.TrimSpace(in.Channel)
	}
	c.Update.Mode = in.Mode
	if strings.TrimSpace(in.CheckInterval) != "" {
		c.Update.CheckInterval = strings.TrimSpace(in.CheckInterval)
	}
	c.Update.Proxy = strings.TrimSpace(in.Proxy)
	c.Proxy.Username, c.Proxy.Password = "", "" // creds never go into YAML

	b, err := yaml.Marshal(c)
	if err != nil {
		return result{false, err.Error()}
	}
	if _, err := config.Parse(b); err != nil {
		return result{false, err.Error()}
	}
	if resp, err := ipc.Call(a.pipe, ipc.Request{Op: ipc.OpSetConfig, Args: map[string]string{"yaml": string(b)}}, callTimeout); err != nil || !resp.OK {
		if werr := os.WriteFile(a.configPath, b, 0o600); werr != nil {
			return result{false, a.tr("could not write the config file: ", "не удалось записать файл конфигурации: ") + werr.Error()}
		}
		return result{true, a.tr("Saved to file — applies when the service starts.", "Сохранено в файл — применится при старте службы.")}
	}
	return result{true, a.tr("Saved.", "Сохранено.")}
}

// updateStatus returns the service's cached check result (fast) as raw JSON.
func (a *app) updateStatus() json.RawMessage {
	if resp, err := ipc.Call(a.pipe, ipc.Request{Op: ipc.OpUpdateStatus}, callTimeout); err == nil && resp.OK {
		return json.RawMessage(resp.Data)
	}
	b, _ := json.Marshal(map[string]any{"current": a.version})
	return json.RawMessage(b)
}

// startUpdateCheck runs a check via the service (network, up to ~25s) off the UI
// thread and resolves with the raw Result JSON.
func (a *app) startUpdateCheck(id string) {
	go func() {
		resp, err := ipc.Call(a.pipe, ipc.Request{Op: ipc.OpUpdateCheck}, 30*time.Second)
		if err != nil || !resp.OK {
			a.resolve(id, map[string]any{"error": a.tr("the service is not reachable", "служба недоступна")})
			return
		}
		a.resolve(id, json.RawMessage(resp.Data))
	}()
}

// startUpdateApply asks the service to download and apply the update. The service
// restarts to finish, so the pipe may drop right after — the UI re-polls status.
func (a *app) startUpdateApply(id string) {
	go func() {
		resp, err := ipc.Call(a.pipe, ipc.Request{Op: ipc.OpUpdateApply}, 6*time.Minute)
		if err != nil || !resp.OK {
			a.resolve(id, map[string]any{"ok": false, "message": a.tr("the service is not reachable (it may be restarting to apply the update)", "служба недоступна (возможно, перезапускается для установки обновления)")})
			return
		}
		a.resolve(id, json.RawMessage(resp.Data))
	}()
}

// resolve delivers an async job result to the JS side on the UI thread.
func (a *app) resolve(id string, payload any) {
	b, _ := json.Marshal(payload)
	js := "window.__result(" + jsStr(id) + "," + string(b) + ")"
	a.w.Dispatch(func() { a.w.Eval(js) })
}

// ---- fast bindings ----

func (a *app) state() stateView {
	installed, running, _ := service.Status()
	s := stateView{Installed: installed, Running: running, Elevated: isElevated(), Engine: "down", Version: a.version, ShowTray: true, Mode: config.ModeAllowlist}
	if b, err := os.ReadFile(a.configPath); err == nil {
		c := config.ParseLenient(b)
		s.Proxy = proxyStr(c)
		s.Apps = len(c.Apps)
		s.Mode = c.Mode
		s.KillSwitch = c.KillSwitchOn()
		s.ShowTray = c.ShowTrayEnabled()
	} else {
		s.Proxy = "(not set)"
	}
	if resp, err := ipc.Call(a.pipe, ipc.Request{Op: ipc.OpStatus}, callTimeout); err == nil && resp.OK {
		var st ipcStatus
		if json.Unmarshal(resp.Data, &st) == nil {
			s.Enabled = st.Enabled
			s.PID = st.PID
			// Show the RUNNING service's version — that's what updates compare and
			// replace. It can differ from this panel binary's version (e.g. a dev
			// panel run against an installed service); the panel value is the fallback.
			if st.Version != "" {
				s.Version = st.Version
			}
			switch {
			case !st.Enabled:
				s.Engine = "paused"
			case st.State == "running":
				s.Engine = "up"
			default:
				s.Engine = st.State
			}
		}
	}
	s.StatusText = statusSummary(s)
	return s
}

func (a *app) getConfig() configView {
	c := a.loadConfig()
	return configView{
		Address:          c.Proxy.Address,
		Port:             c.Proxy.Port,
		Mode:             c.Mode,
		KillSwitch:       c.KillSwitchOn(),
		ShowTray:         c.ShowTrayEnabled(),
		UDP:              c.UDPEnabled(),
		DirectSubnets:    nonNil(c.DirectSubnets),
		Apps:             nonNil(c.Apps),
		CfgURL:           c.ConfigSource.URL,
		CfgInterval:      c.ConfigSource.Interval,
		CfgSigned:        c.ConfigSigned(),
		CfgPubKey:        c.ConfigSource.PubKey,
		CfgMerge:         c.MergeMode(),
		CfgProxy:         c.ConfigSource.Proxy,
		CfgPendingPubKey: c.ConfigSource.PendingPubKey,
		ManagedApps:      nonNil(c.ManagedApps),
		ManagedSubnets:   nonNil(c.ManagedSubnets),
		CfgLocked:        nonNil(c.ConfigSource.Locked),
	}
}

func (a *app) saveConfig(in saveInput) result {
	c := a.loadConfig()
	c.Proxy.Address = strings.TrimSpace(in.Address)
	if in.Port > 0 {
		c.Proxy.Port = in.Port
	} else {
		c.Proxy.Port = 1080
	}
	c.Proxy.Username, c.Proxy.Password = "", "" // creds never go into YAML
	udp := in.UDP
	c.Proxy.UDP = &udp
	c.Mode = in.Mode
	ks := in.KillSwitch
	c.KillSwitch = &ks
	tray := in.ShowTray
	c.ShowTray = &tray
	c.DirectSubnets = cleanList(in.DirectSubnets)
	c.Apps = cleanList(in.Apps)
	c.ConfigSource.URL = strings.TrimSpace(in.CfgURL)
	if strings.TrimSpace(in.CfgInterval) != "" {
		c.ConfigSource.Interval = strings.TrimSpace(in.CfgInterval)
	}
	cs := in.CfgSigned
	c.ConfigSource.Signed = &cs
	c.ConfigSource.PubKey = strings.TrimSpace(in.CfgPubKey)
	if strings.EqualFold(strings.TrimSpace(in.CfgMerge), config.MergeReplace) {
		c.ConfigSource.Merge = config.MergeReplace
	} else {
		c.ConfigSource.Merge = config.MergeOverride // default
	}
	c.ConfigSource.Proxy = strings.TrimSpace(in.CfgProxy)

	b, err := yaml.Marshal(c)
	if err != nil {
		return result{false, err.Error()}
	}
	if _, err := config.Parse(b); err != nil {
		return result{false, err.Error()}
	}

	savedToFile := false
	if resp, err := ipc.Call(a.pipe, ipc.Request{Op: ipc.OpSetConfig, Args: map[string]string{"yaml": string(b)}}, callTimeout); err != nil || !resp.OK {
		if werr := os.WriteFile(a.configPath, b, 0o600); werr != nil {
			return result{false, a.tr("service is not running, and the config file could not be written: ",
				"служба не запущена, и не удалось записать файл конфигурации: ") + werr.Error()}
		}
		savedToFile = true
	}

	credMsg := ""
	if strings.TrimSpace(in.Username) != "" || in.Password != "" {
		if r, err := ipc.Call(a.pipe, ipc.Request{Op: ipc.OpSetCreds, Args: map[string]string{"user": strings.TrimSpace(in.Username), "pass": in.Password}}, callTimeout); err != nil || !r.OK {
			credMsg = a.tr(" Credentials need a running service — start it, then re-enter them.",
				" Для учётных данных нужна работающая служба — запустите её и введите заново.")
		} else {
			credMsg = a.tr(" Credentials updated.", " Учётные данные обновлены.")
		}
	}
	if savedToFile {
		return result{true, a.tr("Saved to file — the service is not running, so it will apply on start.",
			"Сохранено в файл — служба не запущена, применится при старте.") + credMsg}
	}
	return result{true, a.tr("Saved and applied.", "Сохранено и применено.") + credMsg}
}

func (a *app) toggleProxying(on bool) result {
	next := "false"
	if on {
		next = "true"
	}
	if r, err := ipc.Call(a.pipe, ipc.Request{Op: ipc.OpToggle, Args: map[string]string{"on": next}}, callTimeout); err != nil || !r.OK {
		return result{false, a.tr("the service is not reachable", "служба недоступна")}
	}
	return result{true, ""}
}

func (a *app) reload() result {
	if r, err := ipc.Call(a.pipe, ipc.Request{Op: ipc.OpReload}, callTimeout); err != nil || !r.OK {
		return result{false, a.tr("the service is not reachable", "служба недоступна")}
	}
	return result{true, a.tr("Reload requested.", "Запрошена перезагрузка.")}
}

type logView struct {
	Text string `json:"text"`
}

func (a *app) logs(maxLines int) logView {
	if maxLines <= 0 || maxLines > 5000 {
		maxLines = 500
	}
	path := filepath.Join(a.dataDir, "socksit.log")
	b, err := os.ReadFile(path)
	if err != nil {
		return logView{Text: "(no log yet at " + path + ")"}
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return logView{Text: strings.Join(lines, "\n")}
}

// uiPrefs is the per-user UI state stored in ui.json (theme + language).
type uiPrefs struct {
	Theme string `json:"theme"`
	Lang  string `json:"lang"`
}

func (a *app) loadUIPrefs() uiPrefs {
	p := uiPrefs{Theme: "system"}
	if b, err := os.ReadFile(a.prefsFile()); err == nil {
		_ = json.Unmarshal(b, &p)
	}
	if p.Theme == "" {
		p.Theme = "system"
	}
	return p
}

func (a *app) saveUIPrefs(p uiPrefs) error {
	_ = os.MkdirAll(filepath.Dir(a.prefsFile()), 0o755)
	b, _ := json.Marshal(p)
	return os.WriteFile(a.prefsFile(), b, 0o644)
}

func (a *app) getTheme() string { return a.loadUIPrefs().Theme }

func (a *app) setTheme(t string) result {
	p := a.loadUIPrefs()
	p.Theme = t
	if err := a.saveUIPrefs(p); err != nil {
		return result{false, err.Error()}
	}
	return result{true, ""}
}

func (a *app) getLang() string { return a.loadUIPrefs().Lang }

func (a *app) setLang(l string) result {
	a.lang = l
	p := a.loadUIPrefs()
	p.Lang = l
	if err := a.saveUIPrefs(p); err != nil {
		return result{false, err.Error()}
	}
	return result{true, ""}
}

func (a *app) elevate() result {
	exe := executablePath()
	// Release our singleton first so the elevated instance can claim it (otherwise
	// it would see the mutex and just focus this dying window).
	if panelMutex != 0 {
		windows.CloseHandle(panelMutex)
		panelMutex = 0
	}
	if err := relaunchElevated(exe); err != nil {
		return result{false, err.Error()}
	}
	a.w.Terminate() // hand off to the elevated instance
	return result{true, ""}
}

// restartForUpdate relaunches the freshly-installed binary and closes this panel.
// After an in-place update the running panel is still the OLD exe; the new one
// sits at InstallDir()\socksit.exe, so we launch that and exit. The singleton is
// released first so the new instance claims it instead of just focusing this
// dying window.
func (a *app) restartForUpdate() result {
	target := filepath.Join(service.InstallDir(), "socksit.exe")
	if _, err := os.Stat(target); err != nil {
		target = executablePath() // fall back to our own path
	}
	if panelMutex != 0 {
		windows.CloseHandle(panelMutex)
		panelMutex = 0
	}
	verb, _ := windows.UTF16PtrFromString("open")
	file, _ := windows.UTF16PtrFromString(target)
	if err := windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL); err != nil {
		acquireSingleton() // launch failed; keep holding the singleton and stay open
		return result{false, err.Error()}
	}
	a.w.Terminate() // hand off to the new instance
	return result{true, ""}
}

// acceptKeyRotation applies a pending managed key rotation — it moves the root of
// trust to the server-proposed key. Requires explicit admin approval (this call).
func (a *app) acceptKeyRotation() result {
	c := a.loadConfig()
	pk := strings.TrimSpace(c.ConfigSource.PendingPubKey)
	if pk == "" {
		return result{false, a.tr("no key rotation is pending", "нет ожидающей смены ключа")}
	}
	c.ConfigSource.PubKey = pk
	c.ConfigSource.PendingPubKey = ""
	c.ConfigSource.DeclinedPubKey = ""
	return a.writeConfigSource(c)
}

// declineKeyRotation rejects a pending rotation; the client stops re-prompting
// for that exact key until the server proposes a different one.
func (a *app) declineKeyRotation() result {
	c := a.loadConfig()
	c.ConfigSource.DeclinedPubKey = strings.TrimSpace(c.ConfigSource.PendingPubKey)
	c.ConfigSource.PendingPubKey = ""
	return a.writeConfigSource(c)
}

// writeConfigSource persists c via the service (falling back to the file).
func (a *app) writeConfigSource(c *config.Config) result {
	b, err := yaml.Marshal(c)
	if err != nil {
		return result{false, err.Error()}
	}
	if _, err := config.Parse(b); err != nil {
		return result{false, err.Error()}
	}
	if resp, err := ipc.Call(a.pipe, ipc.Request{Op: ipc.OpSetConfig, Args: map[string]string{"yaml": string(b)}}, callTimeout); err != nil || !resp.OK {
		if werr := os.WriteFile(a.configPath, b, 0o600); werr != nil {
			return result{false, a.tr("could not write the config file: ", "не удалось записать файл конфигурации: ") + werr.Error()}
		}
	}
	return result{true, ""}
}

// ---- slow (async) bindings ----

func (a *app) startServiceAction(id, action string) {
	go func() {
		exe := executablePath()
		var msg string
		var err error
		switch action {
		case "setup":
			msg, err = service.Setup(exe)
		case "install":
			err = service.Install(exe)
		case "start":
			err = service.Start()
		case "stop":
			err = service.Stop()
		case "uninstall":
			err = service.Uninstall()
		default:
			err = fmt.Errorf("unknown action %q", action)
		}
		if err != nil {
			a.resolve(id, result{false, err.Error()})
			return
		}
		if msg == "" {
			msg = a.tr("Done.", "Готово.")
		}
		a.resolve(id, result{true, msg})
	}()
}

func (a *app) startTestProxy(id, address string, port int, user, pass string) {
	go func() {
		o, err := proxytest.Check(address, port, user, pass)
		a.resolve(id, a.formatProxy(o, err))
	}()
}

// formatProxy renders a localized result from a proxytest Outcome/Fault.
func (a *app) formatProxy(o proxytest.Outcome, err error) result {
	if err != nil {
		return result{false, a.faultMsg(err)}
	}
	reach := a.tr("Proxy "+o.Target+" — reachable ✓", "Прокси "+o.Target+" — доступен ✓")
	auth := a.tr("SOCKS5 handshake OK — no authentication required", "SOCKS5: рукопожатие OK — авторизация не требуется")
	if o.Auth == "userpass" {
		auth = a.tr("SOCKS5 handshake OK — username/password accepted", "SOCKS5: рукопожатие OK — логин/пароль приняты")
	}
	var egress string
	switch o.Egress {
	case "ok":
		egress = a.tr("Egress test (CONNECT 1.1.1.1:443): success ✓ — the proxy forwards traffic",
			"Тест выхода (CONNECT 1.1.1.1:443): успех ✓ — прокси пропускает трафик")
	case "refused":
		egress = a.tr(
			fmt.Sprintf("Egress test: refused (code %d: %s) — the proxy speaks SOCKS5 but blocked the test destination; it may still work for your apps", o.RepCode, replyTextEN(o.RepCode)),
			fmt.Sprintf("Тест выхода: отказ (код %d: %s) — прокси отвечает по SOCKS5, но заблокировал тестовый адрес; для ваших приложений может работать", o.RepCode, replyTextRU(o.RepCode)))
	default:
		egress = a.tr("Egress test: no reply from the proxy", "Тест выхода: нет ответа от прокси")
	}
	return result{true, reach + "\n" + auth + "\n" + egress}
}

// faultMsg localizes a proxytest.Fault.
func (a *app) faultMsg(err error) string {
	f, ok := err.(*proxytest.Fault)
	if !ok {
		return err.Error()
	}
	switch f.Code {
	case "empty_address":
		return a.tr("Proxy address is empty", "Адрес прокси пуст")
	case "bad_port":
		return a.tr("Proxy port is out of range", "Порт прокси вне диапазона")
	case "connect":
		return a.tr("Cannot connect to the proxy", "Не удаётся подключиться к прокси") + ": " + f.Detail
	case "handshake_write":
		return a.tr("Failed to send the SOCKS5 handshake", "Не удалось отправить SOCKS5-приветствие") + ": " + f.Detail
	case "no_reply":
		return a.tr("No SOCKS5 reply (is it really a SOCKS5 proxy?)", "Нет ответа SOCKS5 (это точно SOCKS5-прокси?)") + ": " + f.Detail
	case "not_socks5":
		return a.tr("The server did not answer as SOCKS5", "Сервер ответил не по протоколу SOCKS5") + " (" + f.Detail + ")"
	case "need_creds":
		return a.tr("The proxy requires a username/password — enter them and test again", "Прокси требует логин/пароль — укажите их и повторите")
	case "no_auth_rejected":
		return a.tr("The proxy rejected no-auth — it likely requires a username/password", "Прокси отклонил вход без авторизации — вероятно, нужен логин/пароль")
	case "all_rejected":
		return a.tr("The proxy rejected all offered authentication methods", "Прокси отклонил все предложенные методы авторизации")
	case "unsupported_method":
		return a.tr("The proxy selected an unsupported auth method", "Прокси выбрал неподдерживаемый метод авторизации") + " (" + f.Detail + ")"
	case "creds_too_long":
		return a.tr("Username/password too long for SOCKS5 (max 255 bytes)", "Логин/пароль слишком длинные для SOCKS5 (макс. 255 байт)")
	case "auth_write":
		return a.tr("Failed to send credentials", "Не удалось отправить учётные данные") + ": " + f.Detail
	case "auth_no_reply":
		return a.tr("No reply to authentication", "Нет ответа на авторизацию") + ": " + f.Detail
	case "auth_rejected":
		return a.tr("The proxy rejected the username/password", "Прокси отклонил логин/пароль")
	default:
		return f.Code
	}
}

func replyTextEN(code int) string {
	switch code {
	case 1:
		return "general failure"
	case 2:
		return "connection not allowed by ruleset"
	case 3:
		return "network unreachable"
	case 4:
		return "host unreachable"
	case 5:
		return "connection refused"
	case 6:
		return "TTL expired"
	case 7:
		return "command not supported"
	case 8:
		return "address type not supported"
	default:
		return "unknown"
	}
}

func replyTextRU(code int) string {
	switch code {
	case 1:
		return "общая ошибка"
	case 2:
		return "соединение запрещено правилами"
	case 3:
		return "сеть недоступна"
	case 4:
		return "хост недоступен"
	case 5:
		return "соединение отклонено"
	case 6:
		return "истёк TTL"
	case 7:
		return "команда не поддерживается"
	case 8:
		return "тип адреса не поддерживается"
	default:
		return "неизвестно"
	}
}

func (a *app) startDiagnostics(id string) {
	go func() { a.resolve(id, logView{Text: a.buildDiagnostics()}) }()
}

func (a *app) startStats(id string) {
	go func() {
		rows, totals, err := a.fetchStats()
		if err != nil {
			a.resolve(id, statsView{Error: err.Error()})
			return
		}
		a.resolve(id, statsView{Rows: rows, Totals: totals})
	}()
}

// ---- helpers ----

func (a *app) loadConfig() *config.Config {
	if resp, err := ipc.Call(a.pipe, ipc.Request{Op: ipc.OpGetConfig}, callTimeout); err == nil && resp.OK {
		var text string
		if json.Unmarshal(resp.Data, &text) == nil && strings.TrimSpace(text) != "" {
			return config.ParseLenient([]byte(text))
		}
	}
	if b, err := os.ReadFile(a.configPath); err == nil {
		return config.ParseLenient(b)
	}
	return config.Default()
}

func (a *app) prefsFile() string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base = a.dataDir
	}
	return filepath.Join(base, "SocksIt", "ui.json")
}

func proxyStr(c *config.Config) string {
	addr := strings.TrimSpace(c.Proxy.Address)
	if addr == "" {
		return "(not set)"
	}
	return net.JoinHostPort(addr, strconv.Itoa(c.Proxy.Port))
}

func statusSummary(s stateView) string {
	switch {
	case !s.Installed:
		return "Service not installed"
	case !s.Running:
		return "Service stopped"
	case !s.Enabled:
		return "Proxying paused"
	case s.Engine == "up":
		return "Active — proxying on"
	default:
		return "Tunnel down — proxied apps blocked (kill-switch)"
	}
}

func cleanList(in []string) []string {
	out := []string{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func executablePath() string {
	p, _ := os.Executable()
	return p
}

func isElevated() bool {
	var t windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &t); err != nil {
		return false
	}
	defer t.Close()
	return t.IsElevated()
}

func relaunchElevated(exe string) error {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	return windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}

// ---- diagnostics + stats (self-contained; no walk dependency) ----

func (a *app) buildDiagnostics() string {
	var b strings.Builder
	line := func(f string, args ...any) { fmt.Fprintf(&b, f+"\n", args...) }

	line(a.tr("SocksIt diagnostics", "Диагностика SocksIt"))
	line("===================")

	installed, running, err := service.Status()
	switch {
	case err != nil:
		line("[?] "+a.tr("Service status unknown", "Не удалось определить состояние службы")+": %v", err)
	case !installed:
		line("[x] " + a.tr("Service is NOT installed — use Dashboard → Set up.", "Служба НЕ установлена — «Обзор» → Установить."))
	case !running:
		line("[x] " + a.tr("Service is installed but STOPPED — Dashboard → Start.", "Служба установлена, но ОСТАНОВЛЕНА — «Обзор» → Запустить."))
	default:
		line("[ok] " + a.tr("Service installed and running.", "Служба установлена и работает."))
	}

	var st ipcStatus
	haveStatus := false
	if resp, e := ipc.Call(a.pipe, ipc.Request{Op: ipc.OpStatus}, callTimeout); e == nil && resp.OK {
		haveStatus = json.Unmarshal(resp.Data, &st) == nil
	}
	switch {
	case haveStatus && !st.Enabled:
		line("[x] " + a.tr("Proxying is PAUSED — enable it on the Dashboard.", "Проксирование НА ПАУЗЕ — включите на «Обзор»."))
	case haveStatus && st.State == "running":
		line("[ok] "+a.tr("Engine running (pid %d), proxying enabled.", "Движок работает (pid %d), проксирование включено."), st.PID)
	case haveStatus:
		line("[x] "+a.tr("Engine is %q while enabled — tunnel down, proxied apps blocked by the kill-switch.", "Движок в состоянии %q при включённом проксировании — туннель не поднят, приложения заблокированы kill-switch."), st.State)
		line("     " + a.tr("See the Logs section and the proxy check below.", "Смотрите раздел «Логи» и проверку прокси ниже."))
	case running:
		line("[?] " + a.tr("Service running but the control channel didn't answer (retry shortly).", "Служба работает, но канал управления не ответил (повторите чуть позже)."))
	}

	c := a.loadConfig()
	if _, e := config.Load(a.configPath); e != nil {
		line("[x] "+a.tr("Config is not valid yet", "Конфиг ещё не валиден")+": %v", e)
	}
	addr := strings.TrimSpace(c.Proxy.Address)
	if addr == "" {
		line("[x] " + a.tr("No proxy address set — open Settings and set the SOCKS5 address.", "Адрес прокси не задан — откройте «Настройки» и укажите адрес SOCKS5."))
	} else {
		line("[ok] "+a.tr("Proxy configured: %s:%d (mode: %s, kill-switch: %s).", "Прокси настроен: %s:%d (режим: %s, kill-switch: %s)."), addr, c.Proxy.Port, c.Mode, onOff(c.KillSwitchOn()))
	}

	gen := filepath.Join(a.dataDir, "config.json")
	if fileExists(gen) {
		line("[ok] "+a.tr("Engine config generated: %s", "Конфиг движка сгенерирован: %s"), gen)
	} else {
		line("[x] "+a.tr("No engine config at %s — the service hasn't produced one (invalid config, or not started).", "Нет конфига движка в %s — служба его не создала (невалидный конфиг или не запущена)."), gen)
	}

	if addr != "" {
		o, e := proxytest.Check(addr, c.Proxy.Port, "", "")
		if e != nil {
			line("[x] "+a.tr("Proxy check", "Проверка прокси")+": %s", a.faultMsg(e))
			line("     " + a.tr("(If it needs a username/password, that is expected here — the service uses the stored credentials.)", "(Если нужен логин/пароль — здесь это ожидаемо: служба использует сохранённые учётные данные.)"))
		} else {
			for _, ln := range strings.Split(a.formatProxy(o, nil).Message, "\n") {
				line("     %s", ln)
			}
		}
	}

	line("")
	line(a.tr("Configured apps (%s mode):", "Настроенные приложения (режим %s):"), c.Mode)
	if len(c.Apps) == 0 {
		if c.Mode == config.ModeAllowlist {
			line("  " + a.tr("(none) — nothing is proxied in allowlist mode. Add apps in Settings.", "(нет) — в режиме allowlist ничего не проксируется. Добавьте приложения в «Настройках»."))
		} else {
			line("  " + a.tr("(none) — in blocklist mode every app is proxied.", "(нет) — в режиме blocklist проксируются все приложения."))
		}
	} else {
		set := runningSet()
		for _, app := range c.Apps {
			base := strings.ToLower(filepath.Base(strings.TrimSpace(app)))
			mark := a.tr("not running", "не запущено")
			if set[base] {
				mark = a.tr("RUNNING", "ЗАПУЩЕНО")
			}
			line("  • %s — %s", app, mark)
		}
		line("")
		line(a.tr("Tip: an app is proxied only while its process runs and its name/path matches (case-insensitive).", "Подсказка: приложение проксируется только пока его процесс запущен и имя/путь совпадают (без учёта регистра)."))
		line(a.tr("For web apps (e.g. Claude/ChatGPT in a browser) add the BROWSER process (chrome.exe / msedge.exe).", "Для веб-приложений (Claude/ChatGPT в браузере) добавьте процесс БРАУЗЕРА (chrome.exe / msedge.exe)."))
	}
	return b.String()
}

func runningSet() map[string]bool {
	m := make(map[string]bool)
	for _, n := range proc.Names() {
		m[strings.ToLower(n)] = true
	}
	return m
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// clashConns is the subset of the Clash API /connections payload we render.
type clashConns struct {
	DownloadTotal int64 `json:"downloadTotal"`
	UploadTotal   int64 `json:"uploadTotal"`
	Connections   []struct {
		Upload   int64    `json:"upload"`
		Download int64    `json:"download"`
		Chains   []string `json:"chains"`
		Metadata struct {
			Network         string `json:"network"`
			DestinationIP   string `json:"destinationIP"`
			DestinationPort string `json:"destinationPort"`
			Host            string `json:"host"`
			Process         string `json:"process"`
			ProcessPath     string `json:"processPath"`
		} `json:"metadata"`
	} `json:"connections"`
}

func (a *app) fetchStats() (rows []statRow, totals string, err error) {
	resp, err := ipc.Call(a.pipe, ipc.Request{Op: ipc.OpStats}, callTimeout)
	if err != nil {
		return nil, "", err
	}
	if !resp.OK {
		return nil, "", fmt.Errorf("%s", resp.Error)
	}
	var c clashConns
	if err := json.Unmarshal(resp.Data, &c); err != nil {
		return nil, "", err
	}
	for i := range c.Connections {
		cn := &c.Connections[i]
		p := cn.Metadata.Process
		if p == "" && cn.Metadata.ProcessPath != "" {
			p = filepath.Base(cn.Metadata.ProcessPath)
		}
		dst := cn.Metadata.Host
		if dst == "" {
			dst = cn.Metadata.DestinationIP
		}
		if cn.Metadata.DestinationPort != "" {
			dst += ":" + cn.Metadata.DestinationPort
		}
		rows = append(rows, statRow{
			Process:     p,
			Destination: dst,
			Net:         cn.Metadata.Network,
			Via:         strings.Join(cn.Chains, " → "),
			Up:          humanBytes(cn.Upload),
			Down:        humanBytes(cn.Download),
			UpBytes:     cn.Upload,
			DownBytes:   cn.Download,
		})
	}
	totals = fmt.Sprintf("%d active connections   ↑ %s   ↓ %s", len(rows), humanBytes(c.UploadTotal), humanBytes(c.DownloadTotal))
	return rows, totals, nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

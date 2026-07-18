# SocksIt — build progress (goal tracker)

Tracks execution of `docs/plans/2026-07-13-001-feat-socksit-per-app-socks5-plan.md`.
Local-first pass (no git/CI this round, per plan Delivery / Rollout Notes).

Legend: ✅ done · 🔶 partial (code done, runtime verification owner-run) · ⏳ pending · 🚧 blocked

| Unit | Status | Notes |
|------|--------|-------|
| U1 — engine spike + version pin | ✅ | Schema (polite+greedy) passes `sing-box check`; proxy egress + UDP ASSOCIATE verified live; `default_domain_resolver` requirement found. See `docs/spikes/`. |
| U2 — scaffolding + embedded engine | ✅ | Go module, subcommand CLI, engine staged. `//go:embed` landed behind `-tags embed_engine` (default build 10.6 MB lean; bundled 65.4 MB self-contained) with idempotent runtime extraction — both build+vet verified. |
| U3 — Windows service host | 🔶 | Done (code): `svc.Handler` + `IsWindowsService` branch + `debug.Run`; install/uninstall via `mgr` (LocalSystem, auto). `Runtime` orchestrates reconcile→generate→check→supervise + IPC + self-heal. Build+vet green; full SCM/TUN runtime needs admin (owner-run). |
| U4 — engine supervisor (Job Object) | ✅ | Job Object `KILL_ON_JOB_CLOSE` + context-gated backoff restart + crash-loop breaker; **integration test**: engine up → external kill → restart (new PID) → cancel → port closed (no orphan). |
| U5 — config model + generator + validate + hot-reload | ✅ | Generator + loader + fsnotify watcher; **output passes `sing-box check`** (allowlist/polite, blocklist/greedy+auth, empty). Found: fake-ip cannot be default DNS server → blocklist uses inverted logical-OR match. Adapter name `socksit` (R14). |
| U6 — netstate teardown + self-heal | 🔶 | Done: netmon debounce (**tested**), winipcfg interface/addr/route monitor, netstate stale-adapter detection (**tested**). Adapter removal + route restore is admin-runtime (documented TODO via Wintun API). |
| U7 — DPAPI secret store | ✅ | Encrypt/Decrypt (+entropy), file save/load; tests: round-trip, wrong-entropy fails, file round-trip. |
| U8 — IPC + audit log | ✅ | go-winio pipe + SDDL (deny-by-default), WTS console-SID resolution; server/client round-trip, all ops, **audit records mutations without leaking the credential value** — all tested. |
| U9 — tray app | ✅ (code) | `fyne.io/systray` — **pure Go on Windows, no cgo needed**. Status/toggle/reload/open-config/open-app-list/quit; kill-switch-blocking state surfaced (finding #4). Build+vet green; visual render is owner-verified. |
| U10 — GUI (app list + stats) | ✅ (code) | `lxn/walk` (pure Go) app-list editor (add/remove/save via IPC) + stats window (Clash API passthrough). Build+vet green; visual render owner-verified. |
| U11 — signed installer + first-run | 🔶 | Source authored: `build/installer.wxs` (WiX v4 schema: ServiceInstall/ServiceControl LocalSystem + tray autostart + bundled engine), `build/build-msi.ps1`, `build/sign.ps1`. **MSI build needs .NET SDK + WiX (SDK absent here); install/uninstall test needs admin + cert** → owner/CI. |
| U12 — CI/CD + docs + manifest | 🔶 | Done: DOC-1/3/4 (`docs/README.md`, `install.md`, `usage.md`) + `requirements-baseline.yaml` records all N/A/applicable/scheduled decisions with resolutions. CI/GitLab pipeline `scheduled` (local-first, owner decision). |

## Environment findings
- **Go 1.26.5**: installed (portable zip at scratch; not on system PATH — build via that path).
- **C compiler (gcc): absent** — hard blocker for cgo (U9/U10 systray+Fyne) until a mingw/TDM-GCC toolchain is added (`choco install mingw`).
- **WiX: absent** — needed for U11 (installable via `dotnet tool install --global wix` or choco).
- winget + choco available; GitHub + Go proxy reachable; sing-box v1.13.14 obtained + staged.
- Admin/LocalSystem + real TUN required for live datapath acceptance (AE1–AE7) and service runtime — owner-run per plan.

## Terminal state — remaining DoD gaps are environment-gated (verified, not assumed)

All code (U1–U12) is written and builds; 8 packages pass tests; UI is pure-Go (no cgo).
The two unmet DoD items cannot be done from this environment — confirmed empirically:

- **AE1–AE8 live acceptance + run-as-LocalSystem** — needs admin. Probe: `elevated:false`.
  Wintun TUN opens only as SYSTEM; SCM install needs admin. Owner-run per plan Delivery Notes.
  Turnkey procedure written: `docs/acceptance-AE.md` (uses the real proxy 192.0.2.10:1080).
- **Signed installer built from CI** — three independent walls: (1) no signing cert (owner/CI);
  (2) MSI build needs .NET SDK + WiX, but `builds.dotnet.microsoft.com` is **unreachable** from
  here (download timeout) and no local WiX/NSIS/msbuild exists; (3) install/uninstall test needs
  admin. Installer source + scripts are authored (`build/`); building + signing + install-verify
  is owner/CI. Unsigned build is the plan's accepted fallback.

These are resource/network/privilege limits, not open work items. Everything achievable without
admin, a cert, or the blocked .NET host has been completed.

## Design corrections found during real testing (owner machine)

- **`polite` removed — single mode `greedy` (full capture).** The plan's `polite` (fake-ip-CIDR
  route only) cannot intercept DNS, so fake-ip is never assigned and nothing proxies — confirmed on
  the owner's machine, first with `strict_route` off and then WITH `strict_route` on (still failed).
  Removed the mode entirely; `coexistence` is now deprecated — still accepted so old configs parse,
  but cleared on load and never re-emitted (dropped from the config schema/template). SocksIt does
  not coexist with a full-tunnel VPN (fake-ip needs DNS hijack, incompatible with leaving another
  VPN's route/DNS untouched). Supersedes plan R6/KTD3.

- **Data vs. program files kept separate (by design).** Binaries + engine → `%ProgramFiles%\SocksIt`;
  config/logs/secrets → `%ProgramData%\SocksIt`. Program Files is read-only for standard users, so
  consolidating there would break user-session GUI config saves and force elevation for every edit.
  The service grants interactive users Modify on the data dir (`icacls`) so the GUI can save
  `socksit.yaml` directly when the service is stopped; secrets stay safe (DPAPI, SYSTEM-only).

- **GUI saves without a running service.** Edit Settings tries the service over IPC first; if it is
  down, it writes `socksit.yaml` directly (the service applies it on next start). Credentials still
  require the running service (DPAPI).
- **Removed netmon → engine-restart self-heal.** It reacted to sing-box's own auto_route edits and
  restarted the engine every ~2s (proxy worked a few seconds then dropped). Network-change handling
  is delegated to sing-box `auto_detect_interface`. Supersedes plan U6 self-heal wiring.
- **Engine/service output now logged** to `%ProgramData%\SocksIt\socksit.log` (was lost before).
- **Manifest embedded** (`cmd/socksit/rsrc_windows_amd64.syso`) — required by walk (fixed `TTM_ADDTOOL`).

## Hybrid GUI/CLI launcher

- No-arg launch opens the **control panel** (`gui.RunControlPanel`): service install/uninstall/
  start/stop (UAC relaunch when not elevated), plus Edit settings / open config / open logs.
- Release build uses the **GUI subsystem**: `go build -ldflags="-H=windowsgui" -o bin/socksit.exe ./cmd/socksit`
  (clean double-click, no console flash). CLI subcommands still print: `attachParentConsole()`
  attaches to the launching console when stdout isn't already redirected. Verified: `version`/`check`
  print correctly when redirected/piped.
- Service log made console-independent (`safeMulti`) so the GUI-subsystem service still logs to file.

## Verified so far (this session)
- `go build ./...`, `go vet ./...`, `go test ./...` all green (CGO disabled).
- `bin/socksit.exe gen -c docs/socksit.example.yaml` → valid config; `... check` passes against staged engine.
- Live: SOCKS5 proxy `192.0.2.10:1080` reachable, no-auth, **UDP ASSOCIATE supported**; egress IP changes through it.

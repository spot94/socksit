# Building turnkey installer packages (with a preset)

Goal: the end user runs one thing and everything is configured — proxy, apps,
bypass subnets — no manual setup. You (the distributor) bake the settings into a
**preset**.

## End-user experience (both shapes)

Run once **as administrator**: double-click the exe → control panel → **Set up**
(or `socksit setup` for silent/MDM). It:
1. installs the service into `C:\Program Files\SocksIt\` (copies exe + engine),
2. applies your preset to `C:\ProgramData\SocksIt\socksit.yaml`,
3. starts the service.

Done — proxying works with your settings. The panel offers **Restart as
administrator** if launched without elevation.

## Prerequisites (build machine)

- Go toolchain; run from the repo root.
- Engine staged at `assets/bin/sing-box.exe` (+ `libcronet.dll`) — already in the repo.

## Shape A — single self-contained exe (engine + preset embedded)

One file, ~70 MB. Best for end users; one build per distinct preset.

1. Copy `build/preset.example.yaml` to `internal/preset/preset.yaml` and edit it.
2. Build:
   ```powershell
   go build -tags "preset embed_engine" -ldflags="-H=windowsgui" -o socksit-setup.exe ./cmd/socksit
   ```
3. Distribute the single `socksit-setup.exe`. End user: run it → **Set up**.

## Shape B — bundle (exe + editable preset.yaml)

One build, many presets — just edit the YAML. Ships as a folder/zip.

1. Build the normal binary (no per-preset rebuild):
   ```powershell
   go build -ldflags="-H=windowsgui" -o socksit.exe ./cmd/socksit
   ```
2. Copy `build/preset.example.yaml` to `socksit.preset.yaml`, edit it.
3. Ship these together (folder or zip):
   `socksit.exe`, `socksit.preset.yaml`, `sing-box.exe`, `libcronet.dll`.
   End user: run `socksit.exe` → **Set up** (it reads the sibling preset).

## Notes

- **Precedence:** an embedded preset (Shape A) wins over a sibling
  `socksit.preset.yaml` (Shape B).
- **Process names:** in the preset, `apps` must be exact running-process EXE names
  (with `.exe`). For AI/web apps used in a browser, list the browser
  (`chrome.exe` / `msedge.exe`) — routing is per-process, not per-site.
- **Silent / MDM:** `socksit setup` runs and exits (GUI-subsystem build shows no
  window). Deploy via GPO/Intune as an elevated one-shot.
- **Re-running Set up** re-applies the preset (overwrites `socksit.yaml`); users can
  still change settings later in the panel.
- **Signing:** sign `socksit.exe` / `socksit-setup.exe` with your code-signing
  certificate to avoid SmartScreen warnings (see [install.md](install.md)). Not
  required for it to function.
- **Data location** (`C:\ProgramData\SocksIt\`: config, logs, secrets) is fixed and
  independent of where the exe lives.

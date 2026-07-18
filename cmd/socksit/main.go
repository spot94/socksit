// Command socksit is the single binary for the SocksIt service, tray, GUI and
// CLI. The command surface is a small subcommand tree (see cli.go): service
// lifecycle (install/start/stop/status/…), config editing (config show/apply/
// app/subnet), and diagnostics (doctor/proxytest/logs), plus the hidden
// machine-invoked entrypoints `service` (SCM) and `update-restart` (updater).
// Run `socksit help` for the full list.
package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"socksit/assets"
	"socksit/internal/ipc"
	"socksit/internal/service"
	"socksit/ui/panel"
)

// Version is the SocksIt build version, overridden at release time via
// -ldflags "-X main.Version=X.Y.Z". It MUST be a var (not const) — the linker's
// -X flag cannot patch a constant. Keep this "<next release>-dev" so an untagged
// local build reads as newer than the last release, not as an old version.
var Version = "0.1.4-dev"

func main() {
	if len(os.Args) < 2 {
		runNoArgs()
		return
	}
	attachParentConsole() // CLI mode: route output to the launching terminal (GUI-subsystem build)
	if err := dispatch("", buildCLI(), os.Args[1:]); err != nil {
		if msg := err.Error(); msg != "" { // errSilent carries no message (usage already printed)
			fmt.Fprintln(os.Stderr, "error:", msg)
		}
		os.Exit(1)
	}
}

// runNoArgs handles a no-argument launch: run under the SCM if we were started
// as a service, otherwise open the interactive control panel (double-click / terminal).
func runNoArgs() {
	if isSvc, _ := svc.IsWindowsService(); isSvc {
		if err := service.Run(buildRuntime()); err != nil {
			fatal(err)
		}
		return
	}
	dd := defaultDataDir()
	if err := panel.Run(ipc.DefaultPipeName, filepath.Join(dd, "socksit.yaml"), dd, Version, "dashboard"); err != nil {
		fatal(err)
	}
}

// buildRuntime assembles the service Runtime from the environment.
func buildRuntime() *service.Runtime {
	actor := "local"
	if u, err := user.Current(); err == nil {
		actor = u.Username
	}
	dataDir := defaultDataDir()
	enginePath := defaultEngine()
	// Release builds (-tags embed_engine) carry the engine inside the binary;
	// extract it next to the data dir and prefer that copy.
	if assets.Embedded() {
		if p, err := assets.Extract(filepath.Join(dataDir, "bin")); err == nil {
			enginePath = p
		}
	}
	return &service.Runtime{
		DataDir:    dataDir,
		EnginePath: enginePath,
		PipeName:   ipc.DefaultPipeName,
		Actor:      actor,
		Version:    Version,
	}
}

func defaultDataDir() string { return filepath.Join(os.Getenv("ProgramData"), "SocksIt") }

// defaultEngine resolves the staged engine binary: $SOCKSIT_ENGINE, else
// assets/bin/sing-box.exe next to the executable or CWD.
func defaultEngine() string {
	if p := os.Getenv("SOCKSIT_ENGINE"); p != "" {
		return p
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, cand := range []string{
			filepath.Join(dir, "sing-box.exe"),                  // installer flat layout
			filepath.Join(dir, "assets", "bin", "sing-box.exe"), // dev layout next to binary
		} {
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
		}
	}
	return filepath.Join("assets", "bin", "sing-box.exe")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// attachParentConsole routes CLI output to the launching terminal. The exe is
// built for the GUI subsystem (so a double-click opens the panel without a
// console flash); without this, output from `socksit version|status|…` run from
// a console would be invisible. A no-op when there is no parent console.
func attachParentConsole() {
	// If stdout is already valid (redirected to a pipe/file, or a real inherited
	// console), leave it — reopening CONOUT$ would steal redirected output.
	invalid := ^windows.Handle(0)
	if h, _ := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE); h != 0 && h != invalid {
		return
	}
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")
	if r, _, _ := proc.Call(uintptr(0xFFFFFFFF)); r == 0 { // ATTACH_PARENT_PROCESS
		return // no parent console (double-clicked) — nothing to attach
	}
	if out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = out
		os.Stderr = out
	}
	if in, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = in
	}
}

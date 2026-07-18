// Command socksit is the single binary for the SocksIt service, tray, and CLI
// helpers. Subcommands: version | gen | check | service | run | install |
// uninstall | tray. Only version/gen/check are implemented in this pass; the
// service/tray/install commands are stubs pending U3/U9/U11.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"socksit/assets"
	"socksit/internal/config"
	"socksit/internal/ipc"
	"socksit/internal/service"
	"socksit/internal/singbox"
	"socksit/ui/panel"
	"socksit/ui/tray"
)

// Version is the SocksIt build version (independent of the embedded engine).
const Version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		runNoArgs()
		return
	}
	attachParentConsole() // CLI mode: route output to the launching terminal (GUI-subsystem build)
	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Printf("socksit %s (engine sing-box v1.13.14)\n", Version)
	case "gen":
		mustRun(genCmd(os.Args[2:]))
	case "check":
		mustRun(checkCmd(os.Args[2:]))
	case "service":
		rt := buildRuntime()
		isSvc, err := svc.IsWindowsService()
		if err != nil {
			mustRun(err)
		}
		if isSvc {
			mustRun(service.Run(rt))
		} else {
			mustRun(service.RunInteractive(rt))
		}
	case "run":
		mustRun(service.RunInteractive(buildRuntime()))
	case "install":
		exe, err := os.Executable()
		if err != nil {
			mustRun(err)
		}
		mustRun(service.Install(exe))
		fmt.Println("installed service", service.ServiceName)
	case "uninstall":
		mustRun(service.Uninstall())
		fmt.Println("removed service", service.ServiceName)
	case "setup":
		exe, err := os.Executable()
		if err != nil {
			mustRun(err)
		}
		summary, err := service.Setup(exe)
		mustRun(err)
		fmt.Println("setup complete:", summary)
	case "tray":
		tray.Run(ipc.DefaultPipeName, Version)
	case "gui":
		dd := defaultDataDir()
		mustRun(panel.Run(ipc.DefaultPipeName, filepath.Join(dd, "socksit.yaml"), dd, Version, "settings"))
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `socksit — per-app SOCKS5 proxifier

usage:
  socksit                                            (no arguments) open the control panel
  socksit version
  socksit gen   -c socksit.yaml [-o config.json]     generate a sing-box config
  socksit check -c socksit.yaml [-engine sing-box.exe] validate the generated config
  socksit setup                                       turnkey: install + apply preset + start (admin)
  socksit install | uninstall                         register/remove the Windows service
  socksit service                                     run under the SCM (or console if interactive)
  socksit run                                          run interactively for development
  socksit tray                                        user-session tray UI
  socksit gui                                          app-list editor + statistics window
`)
}

// genCmd generates a sing-box config.json from a socksit.yaml.
func genCmd(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	in := fs.String("c", "socksit.yaml", "path to socksit.yaml")
	out := fs.String("o", "", "output path (default: stdout)")
	fs.Parse(args)

	c, err := config.Load(*in)
	if err != nil {
		return err
	}
	js, err := singbox.GenerateJSON(c)
	if err != nil {
		return err
	}
	if *out == "" {
		_, err = os.Stdout.Write(js)
		return err
	}
	return os.WriteFile(*out, js, 0o600)
}

// checkCmd generates and validates a config with `sing-box check`.
func checkCmd(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	in := fs.String("c", "socksit.yaml", "path to socksit.yaml")
	engine := fs.String("engine", defaultEngine(), "path to sing-box.exe")
	fs.Parse(args)

	c, err := config.Load(*in)
	if err != nil {
		return err
	}
	js, err := singbox.GenerateJSON(c)
	if err != nil {
		return err
	}
	if err := singbox.CheckBytes(*engine, js); err != nil {
		return err
	}
	fmt.Println("OK: generated config passes sing-box check")
	return nil
}

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

// runNoArgs handles a no-argument launch: run under the SCM if we were started
// as a service, otherwise open the interactive control panel (double-click / terminal).
func runNoArgs() {
	if isSvc, _ := svc.IsWindowsService(); isSvc {
		mustRun(service.Run(buildRuntime()))
		return
	}
	dd := defaultDataDir()
	mustRun(panel.Run(ipc.DefaultPipeName, filepath.Join(dd, "socksit.yaml"), dd, Version, "dashboard"))
}

func defaultDataDir() string { return filepath.Join(os.Getenv("ProgramData"), "SocksIt") }

// attachParentConsole routes CLI output to the launching terminal. The exe is
// built for the GUI subsystem (so a double-click opens the panel without a
// console flash); without this, output from `socksit version|gen|check|…` run
// from a console would be invisible. A no-op when there is no parent console.
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

func mustRun(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

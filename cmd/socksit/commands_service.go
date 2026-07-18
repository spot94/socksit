package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"

	"socksit/internal/ipc"
	"socksit/internal/service"
)

func cmdInstall(path string, args []string) error {
	_ = newFlagSet(path, "", "register the Windows service").Parse(args)
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := service.Install(exe); err != nil {
		return err
	}
	fmt.Println("installed service", service.ServiceName)
	return nil
}

func cmdUninstall(path string, args []string) error {
	_ = newFlagSet(path, "", "remove the Windows service").Parse(args)
	if err := service.Uninstall(); err != nil {
		return err
	}
	fmt.Println("removed service", service.ServiceName)
	return nil
}

func cmdStart(path string, args []string) error {
	_ = newFlagSet(path, "", "start the Windows service").Parse(args)
	if err := service.Start(); err != nil {
		return err
	}
	fmt.Println("service started")
	return nil
}

func cmdStop(path string, args []string) error {
	_ = newFlagSet(path, "", "stop the Windows service").Parse(args)
	if err := service.Stop(); err != nil {
		return err
	}
	fmt.Println("service stopped")
	return nil
}

func cmdRestart(path string, args []string) error {
	_ = newFlagSet(path, "", "restart the Windows service").Parse(args)
	// Stop may report "already stopped"; that is fine for a restart — proceed to
	// start and surface only a start failure.
	_ = service.Stop()
	if err := service.Start(); err != nil {
		return err
	}
	fmt.Println("service restarted")
	return nil
}

func cmdSetup(path string, args []string) error {
	_ = newFlagSet(path, "", "turnkey: install + apply preset + start (needs admin)").Parse(args)
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	summary, err := service.Setup(exe)
	if err != nil {
		return err
	}
	fmt.Println("setup complete:", summary)
	return nil
}

// cmdStatus reports the SCM view (installed/running) plus, when the service is
// reachable, the live tunnel detail from the control pipe.
func cmdStatus(path string, args []string) error {
	fs := newFlagSet(path, "[--json]", "show service + tunnel status")
	asJSON := fs.Bool("json", false, "machine-readable output")
	_ = fs.Parse(args)

	installed, running, err := service.Status()
	if err != nil {
		return err
	}
	out := map[string]any{"installed": installed, "running": running}
	var tunnel map[string]any
	if resp, e := ipcCall(ipc.OpStatus, nil, callTimeout); e == nil && resp.OK {
		if json.Unmarshal(resp.Data, &tunnel) == nil {
			out["tunnel"] = tunnel
		}
	}
	if *asJSON {
		return printJSON(os.Stdout, out)
	}

	fmt.Printf("service:     %s\n", boolWord(installed, "installed", "not installed"))
	fmt.Printf("running:     %s\n", boolWord(running, "yes", "no"))
	if tunnel != nil {
		fmt.Printf("state:       %v\n", tunnel["state"])
		fmt.Printf("proxy:       %v\n", tunnel["proxy"])
		fmt.Printf("apps:        %v (%v mode)\n", tunnel["apps"], tunnel["mode"])
		fmt.Printf("kill-switch: %v\n", tunnel["kill_switch"])
	} else {
		fmt.Println("tunnel:      (control pipe not reachable — service stopped or not elevated)")
	}
	return nil
}

// --- hidden machine entrypoints (do not rename) ---

// cmdService is the SCM entrypoint registered by Install ("<exe> service"). Under
// the SCM it runs as a service; from an elevated console it runs interactively.
func cmdService(path string, args []string) error {
	rt := buildRuntime()
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if isSvc {
		return service.Run(rt)
	}
	return service.RunInteractive(rt)
}

// cmdRun runs the datapath interactively for development.
func cmdRun(path string, args []string) error {
	return service.RunInteractive(buildRuntime())
}

// cmdUpdateRestart is the detached helper spawned by the service to apply an
// update (stop → start the new version, roll back on failure). Runs as SYSTEM.
func cmdUpdateRestart(path string, args []string) error {
	fs := flag.NewFlagSet("update-restart", flag.ExitOnError)
	name := fs.String("service", service.ServiceName, "service name")
	target := fs.String("target", "", "installed socksit.exe path")
	old := fs.String("old", "", "backup (.old) path to roll back from")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return service.RunUpdateRestart(*name, *target, *old)
}

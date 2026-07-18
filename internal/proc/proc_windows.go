//go:build windows

// Package proc enumerates running processes (used by the UI to offer real,
// correctly-spelled executable names to proxy instead of free-typed guesses).
package proc

import (
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Names returns the sorted, de-duplicated set of running process executable
// names (e.g. "chrome.exe"). The process matcher needs the exact image name,
// with ".exe".
func Names() []string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)

	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := windows.Process32First(snap, &e); err != nil {
		return nil
	}
	set := make(map[string]struct{})
	for {
		if name := windows.UTF16ToString(e.ExeFile[:]); name != "" {
			set[name] = struct{}{}
		}
		if err := windows.Process32Next(snap, &e); err != nil {
			break
		}
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		return strings.ToLower(names[i]) < strings.ToLower(names[j])
	})
	return names
}

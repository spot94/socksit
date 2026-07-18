//go:build windows

package engine

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// jobObject wraps a Windows Job Object configured with KILL_ON_JOB_CLOSE, so
// every process assigned to it (and their children) is terminated by the OS the
// instant the last job handle closes — including if the supervisor crashes.
// See plan KTD6.
type jobObject struct {
	handle windows.Handle
}

// newKillOnCloseJob creates a job with the kill-on-close limit set.
func newKillOnCloseJob() (*jobObject, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		h,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	return &jobObject{handle: h}, nil
}

// assignPID adds a running process to the job. There is a small race between
// process start and assignment; a future revision should assign at creation via
// PROC_THREAD_ATTRIBUTE_JOB_LIST (plan KTD6).
func (j *jobObject) assignPID(pid int) error {
	ph, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(ph)
	if err := windows.AssignProcessToJobObject(j.handle, ph); err != nil {
		return fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	return nil
}

// terminate kills every process in the job immediately.
func (j *jobObject) terminate() {
	windows.TerminateJobObject(j.handle, 1)
}

// close releases the job handle. Because of KILL_ON_JOB_CLOSE, this also kills
// any surviving job members.
func (j *jobObject) close() {
	if j.handle != 0 {
		windows.CloseHandle(j.handle)
		j.handle = 0
	}
}

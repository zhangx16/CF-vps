//go:build windows

package main

import (
	"os/exec"
	"syscall"
	"unsafe"
)

func prepareCommand(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} }
func attachProcess(cmd *exec.Cmd) func() {
	k := syscall.NewLazyDLL("kernel32.dll")
	closeHandle := k.NewProc("CloseHandle")
	job, _, _ := k.NewProc("CreateJobObjectW").Call(0, 0)
	if job == 0 {
		return func() {}
	}
	type basic struct {
		ProcessTime, JobTime int64
		Flags                uint32
		Min, Max             uintptr
		Active               uint32
		Affinity             uintptr
		Priority, Scheduling uint32
	}
	type limits struct {
		Basic                                          basic
		IO                                             [6]uint64
		ProcessMemory, JobMemory, PeakProcess, PeakJob uintptr
	}
	info := limits{}
	info.Basic.Flags = 0x2000
	ok, _, _ := k.NewProc("SetInformationJobObject").Call(job, 9, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if ok == 0 {
		closeHandle.Call(job)
		return func() {}
	}
	p, _, _ := k.NewProc("OpenProcess").Call(0x0100|0x0001, 0, uintptr(cmd.Process.Pid))
	if p != 0 {
		k.NewProc("AssignProcessToJobObject").Call(job, p)
		closeHandle.Call(p)
	}
	return func() { closeHandle.Call(job) }
}
func openBrowser(url string) {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	prepareCommand(cmd)
	cmd.Start()
}

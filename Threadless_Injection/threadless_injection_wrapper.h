// threadless_injection_wrapper.h

#ifndef THREADLESS_INJECTION_WRAPPER_H
#define THREADLESS_INJECTION_WRAPPER_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) DWORD find_process(const char* process_name);
__declspec(dllexport) void write_shellcode(HANDLE h_process, void* address);
__declspec(dllexport) void install_trampoline(HANDLE h_process, void* address, void* function_address);
__declspec(dllexport) void* find_memory_role(SIZE_T func_address, HANDLE h_process);

#ifdef __cplusplus
}
#endif

#endif // THREADLESS_INJECTION_WRAPPER_H

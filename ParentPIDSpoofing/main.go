package main

/*
#cgo CFLAGS: -DUNICODE
#cgo LDFLAGS: -lpsapi -lkernel32

#include <windows.h>
#include <processthreadsapi.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>

#define BUFFER_SIZE 1024

DWORD runningProcessesIDs[BUFFER_SIZE];
DWORD runningProcessesCountBytes;
DWORD runningProcessesCount;
HANDLE hExplorerexe = NULL;

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif

typedef struct _STARTUPINFOEXA {
    STARTUPINFOA StartupInfo;
    PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXA;

BOOL InitializeProcThreadAttributeList(
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    DWORD dwAttributeCount,
    DWORD dwFlags,
    PSIZE_T lpSize
);

BOOL UpdateProcThreadAttribute(
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    DWORD dwFlags,
    DWORD_PTR Attribute,
    PVOID lpValue,
    SIZE_T cbSize,
    PVOID lpPreviousValue,
    PSIZE_T lpReturnSize
);

VOID DeleteProcThreadAttributeList(
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
);

void CreateProcessWithExplorerParent(char* commandLine) {
    EnumProcesses(runningProcessesIDs, sizeof(runningProcessesIDs), &runningProcessesCountBytes);
    runningProcessesCount = runningProcessesCountBytes / sizeof(DWORD);

    for (DWORD i = 0; i < runningProcessesCount; i++) {
        if (runningProcessesIDs[i] != 0) {
            HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, runningProcessesIDs[i]);
            if (hProcess != NULL) {
                char processName[MAX_PATH + 1] = {0};
                if (GetModuleFileNameExA(hProcess, NULL, processName, MAX_PATH)) {
                    _strlwr(processName);
                    if (strstr(processName, "explorer.exe") != NULL) {
                        hExplorerexe = hProcess;
                        break;
                    }
                }
                CloseHandle(hProcess);
            }
        }
    }

    if (hExplorerexe == NULL) {
        printf("Could not find explorer.exe process\n");
        return;
    }

    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T attributeSize = 0;

    ZeroMemory(&si, sizeof(STARTUPINFOEXA));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hExplorerexe, sizeof(HANDLE), NULL, NULL);
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    if (!CreateProcessA(NULL, commandLine, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi)) {
        printf("CreateProcess failed: %d\n", GetLastError());
    } else {
        printf("Process created with PID: %d\n", pi.dwProcessId);
    }

    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hExplorerexe);
}
*/
import "C"
import "unsafe"

func main() {
    commandLine := "C:\\Windows\\System32\\notepad.exe"
    cCommandLine := C.CString(commandLine)
    defer C.free(unsafe.Pointer(cCommandLine))

    C.CreateProcessWithExplorerParent(cCommandLine)
}

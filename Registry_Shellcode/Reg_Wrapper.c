#include <stdio.h>
#include <windows.h>
#include <winreg.h>

void writereg(BYTE *buf, DWORD size) {
    HKEY hkey;
    LONG status = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Control Panel",
        0,
        KEY_SET_VALUE,
        &hkey
    );
    if (status != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyExA Failed With Error: %ld\n", status);
        return;
    }

    status = RegSetValueExA(
        hkey,
        "Evilbytecode",
        0,
        REG_BINARY,
        buf,
        size
    );
    if (status != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA Failed With Error: %ld\n", status);
    } else {
        printf("[+] RegSetValueExA Succeeded\n");
    }

    RegCloseKey(hkey);
}

void readreg() {
    DWORD dataSize = 0;
    DWORD type = REG_BINARY;
    LONG status = RegGetValueA(
        HKEY_CURRENT_USER,
        "Control Panel",
        "Evilbytecode",
        RRF_RT_ANY,
        &type,
        NULL,
        &dataSize
    );
    if (status != ERROR_SUCCESS && status != ERROR_MORE_DATA) {
        printf("[!] RegGetValueA Failed With Error: %ld\n", status);
        return;
    }

    BYTE *data = (BYTE*) malloc(dataSize);
    if (!data) {
        printf("[!] Memory allocation failed\n");
        return;
    }

    status = RegGetValueA(
        HKEY_CURRENT_USER,
        "Control Panel",
        "Evilbytecode",
        RRF_RT_ANY,
        &type,
        data,
        &dataSize
    );
    if (status != ERROR_SUCCESS) {
        printf("[!] RegGetValueA Failed With Error: %ld\n", status);
        free(data);
        return;
    }

    printf("[+] RegGetValueA Succeeded: ");
    for (DWORD i = 0; i < dataSize; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");

    free(data);
}

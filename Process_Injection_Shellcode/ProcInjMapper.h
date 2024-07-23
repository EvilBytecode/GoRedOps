#ifndef PROCINJMAPPER_H
#define PROCINJMAPPER_H

#include <windows.h>

DWORD find_process(const char *name);
BOOL inject_shellcode(DWORD pid, const unsigned char *buf, size_t len);

#endif // PROCINJMAPPER_H

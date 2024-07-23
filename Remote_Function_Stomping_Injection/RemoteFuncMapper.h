// RemoteFuncMapper.h
#ifndef REMOTE_FUNC_MAPPER_H
#define REMOTE_FUNC_MAPPER_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

HANDLE find_process(const char* name);
void inject_shellcode(HANDLE hprocess, unsigned char* shellcode, size_t size);

#ifdef __cplusplus
}
#endif

#endif // REMOTE_FUNC_MAPPER_H

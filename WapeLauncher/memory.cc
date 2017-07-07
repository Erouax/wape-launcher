#include "memory.h"

bool RPM(HANDLE p, LPCVOID i, LPVOID o, SIZE_T n) {
  return NT_SUCCESS(g_api_cache->NTDLL(NTSTATUS, NtReadVirtualMemory,
    p, i, o, n, nullptr));
}

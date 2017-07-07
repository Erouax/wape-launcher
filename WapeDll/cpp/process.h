#pragma once
#include "global.h"
#include <vector>

inline HANDLE OpenProcessWithAccess(const DWORD pid, const ACCESS_MASK access);
inline HANDLE OpenProcessForRead(const DWORD pid);
bool AnyWindowClassRunning(const std::vector<uint32_t>& window_class_hashes);
bool AnyProcessRunning(const std::vector<uint32_t>& process_name_hashes);

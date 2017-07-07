#pragma once
#include "global.h"
#include <unordered_set>
#include <optional>

typedef enum _PEB_OFFSET {
  kCurrentDirectory,
  kCommandLine
} PEB_OFFSET;

struct FPBWCContext {
  explicit FPBWCContext(const uint32_t window_class_hash,
    std::unordered_set<DWORD>* const pids)
    : window_class_hash(window_class_hash)
    , pids(pids)
    , window_class_buffer{0} {
  }

  const uint32_t window_class_hash;
  std::unordered_set<DWORD>* const pids;
  wchar_t window_class_buffer[256 + 1];
};

struct ProcessDetails {
  ProcessDetails(const DWORD pid,
    const std::wstring& current_directory,
    const std::wstring& command_line)
    : pid(pid)
    , current_directory(current_directory)
    , command_line(command_line) {
  }

  const DWORD pid;
  const std::wstring current_directory;
  const std::wstring command_line;
};

inline HANDLE OpenProcessWithAccess(const DWORD pid, const ACCESS_MASK access);
inline HANDLE OpenProcessForRead(const DWORD pid);

std::optional<ProcessDetails> GetProcessDetails(const DWORD pid);

bool FindProcessesByWindowClass(const uint32_t window_class_hash,
  std::unordered_set<DWORD>* const pids);

bool AnyWindowClassRunning(const std::vector<uint32_t>& window_class_hashes);
bool AnyProcessRunning(const std::vector<uint32_t>& process_name_hashes);

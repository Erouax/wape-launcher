#include "process.h"
#include "memory.h"
#include <optional>

PVOID GetPEBPtr(const HANDLE process) {
  PROCESS_BASIC_INFORMATION basic_info = { 0 };
  if (NT_SUCCESS(g_api_cache->NTDLL(NTSTATUS, NtQueryInformationProcess,
    process,
    ProcessBasicInformation,
    &basic_info,
    sizeof(basic_info),
    nullptr))) {
    return basic_info.PebBaseAddress;
  }
  return nullptr;
}

bool GetProcessPebString(const HANDLE process,
  const PEB_OFFSET peb_offset,
  std::wstring* out) {
  ULONG offset;

#define PEB_OFFSET_CASE(e, f) \
  case e: offset = FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, f); break

  switch (peb_offset) {
    PEB_OFFSET_CASE(kCurrentDirectory, CurrentDirectory);
    PEB_OFFSET_CASE(kCommandLine, CommandLine);
  default:
    return false;
  }
#undef PEB_OFFSET_CASE

  auto peb = GetPEBPtr(process);
  if (peb == nullptr) {
    return false;
  }

  PVOID proc_params;

#define PTR_ADD_OFFSET(Pointer, Offset) \
  ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))

  if (!RPM(
    process,
    PTR_ADD_OFFSET(peb, FIELD_OFFSET(PEB, ProcessParameters)),
    &proc_params,
    sizeof(PVOID))) {
    return false;
  }

  auto unicode_string = UNICODE_STRING{};
  if (!RPM(
    process,
    PTR_ADD_OFFSET(proc_params, offset),
    &unicode_string,
    sizeof(UNICODE_STRING))) {
    return false;
  }
#undef PTR_ADD_OFFSET

  auto buffer = g_api_cache->NTDLL(wchar_t*, RtlAllocateHeap,
    g_api_cache->Heap(),
    HEAP_ZERO_MEMORY,
    unicode_string.MaximumLength);
  if (!buffer) {
    return false;
  }

  if (!RPM(
    process,
    unicode_string.Buffer,
    buffer,
    unicode_string.MaximumLength)) {
    g_api_cache->NTDLL(BOOLEAN, RtlFreeHeap, g_api_cache->Heap(), 0, buffer);
    return false;
  }

  *out = std::wstring(buffer, unicode_string.Length / sizeof(wchar_t));
  g_api_cache->NTDLL(BOOLEAN, RtlFreeHeap, g_api_cache->Heap(), 0, buffer);
  return true;
}

HANDLE OpenProcessWithAccess(const DWORD pid, const ACCESS_MASK access) {
	auto handle = INVALID_HANDLE_VALUE;
	auto obj_attr = OBJECT_ATTRIBUTES{};
	auto client_id = CLIENT_ID{};

	InitializeObjectAttributes(&obj_attr, nullptr, 0, nullptr, nullptr);
#pragma warning(push)
#pragma warning(disable: 4312)
	client_id.UniqueProcess = reinterpret_cast<HANDLE>(pid);
#pragma warning(pop)
	client_id.UniqueThread = nullptr;

	const auto status = g_api_cache->NTDLL(NTSTATUS, NtOpenProcess,
																				 &handle,
																				 access,
																				 &obj_attr,
																				 &client_id);
	if (!NT_SUCCESS(status)) {
		handle = INVALID_HANDLE_VALUE;
	}

	return handle;
}

HANDLE OpenProcessForRead(const DWORD pid) {
	return OpenProcessWithAccess(pid, (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ));
}

std::optional<ProcessDetails> GetProcessDetails(const DWORD pid) {
  auto handle = OpenProcessForRead(pid);

  if (handle != INVALID_HANDLE_VALUE) {
    std::wstring current_directory;
    std::wstring command_line;

    GetProcessPebString(handle, kCurrentDirectory, &current_directory);
    GetProcessPebString(handle, kCommandLine, &command_line);
    g_api_cache->NTDLL(NTSTATUS, NtClose, handle);

    return { ProcessDetails(pid,
      current_directory,
      command_line) };
  }

  return {};
}

namespace {
BOOL CALLBACK FPBWCProc(HWND hwnd, FPBWCContext* ctx) {
  if (g_api_cache->U32(int, GetClassNameW,
											 hwnd,
											 ctx->window_class_buffer,
											 sizeof(ctx->window_class_buffer) / sizeof(wchar_t)) > 0) {
    if (cx::crc32(ctx->window_class_buffer) == ctx->window_class_hash) {
      auto process_id = DWORD{0};
      g_api_cache->U32(DWORD, GetWindowThreadProcessId, hwnd, &process_id);
      ctx->pids->emplace(process_id);
    }
  }
  return TRUE;
}
}  // namespace

bool FindProcessesByWindowClass(const uint32_t window_class_hash,
																std::unordered_set<DWORD>* const pids) {
  if (pids) {
    auto context = FPBWCContext{window_class_hash, pids};
    g_api_cache->U32(BOOL, EnumWindows, FPBWCProc, &context);
    return pids->size() > 0;
  }
  return false;
}

namespace {
BOOL CALLBACK AWCRProc(HWND hwnd, LPARAM param) {
	auto should_continue = bool{true};
	char buffer[256 + 1] = {0};
	auto copied = g_api_cache->U32(int, GetClassNameA, hwnd, buffer, sizeof(buffer));

	if (copied > 0) {
		const auto window_class_hash = cx::crc32(buffer, copied, false);

		for (const auto hash : *reinterpret_cast<std::vector<uint32_t>*>(param)) {
			if (window_class_hash == hash) {
				should_continue = false;
				break;
			}
		}
	}

	if (!should_continue) {
		g_api_cache->K32(void, SetLastError, DWORD{1337});
	}

	return should_continue;
}
}  // namespace

bool AnyWindowClassRunning(const std::vector<uint32_t>& window_class_hashes) {
	if (!g_api_cache->U32(BOOL, EnumWindows, AWCRProc, window_class_hashes)) {
		if (g_api_cache->K32(DWORD, GetLastError) == 1337) {
			g_api_cache->K32(void, SetLastError, DWORD{0});
			return true;
		}
	}
	return false;
}

bool AnyProcessRunning(const std::vector<uint32_t>& process_name_hashes) {
	auto result = bool{false};

	auto entries = size_t{512};
	auto buffer = PDWORD{nullptr};
	auto old_buffer = PDWORD{nullptr};
	auto ret = DWORD{0};

	do {
		entries *= 2;

		old_buffer = buffer;
		buffer = reinterpret_cast<PDWORD>(realloc(buffer, entries * sizeof(DWORD)));
		if (!buffer) {
			if (old_buffer) {
				free(old_buffer);
			}
			return false;
		}

		if (!g_api_cache->K32(BOOL, K32EnumProcesses, buffer, entries * sizeof(DWORD), &ret)) {
			ret = 0;
			break;
		}
	} while (ret == entries * sizeof(DWORD));

	for (auto iii = 0u; iii < ret / sizeof(DWORD); iii++) {
		auto process = OpenProcessForRead(buffer[iii]);

		if (process != INVALID_HANDLE_VALUE) {
			char name[256 + 1] = {0};
			auto length = g_api_cache->K32(DWORD, K32GetModuleBaseNameA,
																		 process,
																		 HMODULE{nullptr},
																		 name,
																		 sizeof(name));

			if (length > 0) {
				const auto process_name_hash = cx::crc32(name, length, false);

				for (const auto hash : process_name_hashes) {
					if (process_name_hash == hash) {
						result = true;
						break;
					}
				}
			}

			g_api_cache->K32(BOOL, CloseHandle, process);
		}
	}

	if (buffer) {
		free(buffer);
	}

	return result;
}

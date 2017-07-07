#include "process.h"

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

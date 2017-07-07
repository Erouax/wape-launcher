// https://github.com/stephenfewer/ReflectiveDLLInjection
// modified by jesusnutsack
#include "remote_lib_loader.h"

namespace wape {
namespace launcher {
bool LoadRemoteLibrary(const DWORD pid,
                       const LPVOID localbuf, const SIZE_T length,
                       const ULONG_PTR start_offset, const LPVOID param) {
  auto result = false;
  auto process = HANDLE{nullptr};
  auto obj_attr = OBJECT_ATTRIBUTES{};
  auto client_id = CLIENT_ID{nullptr};
  auto loader_data = ReflectiveLoaderData{};

  InitializeObjectAttributes(&obj_attr, NULL, 0, NULL, NULL);
#pragma warning(push)
#pragma warning(disable: 4312)
  client_id.UniqueProcess = reinterpret_cast<HANDLE>(pid);
#pragma warning(pop)

  auto status = g_api_cache->NTDLL(NTSTATUS, NtOpenProcess,
    &process,
    PROCESS_QUERY_INFORMATION |
    PROCESS_CREATE_THREAD |
    PROCESS_VM_OPERATION |
    PROCESS_VM_WRITE |
		PROCESS_VM_READ,
    &obj_attr,
    &client_id);

  if (NT_SUCCESS(status)) {
    auto remotebuf = PVOID{nullptr};
    auto region_size = SIZE_T{sizeof(loader_data) + length};

    status = g_api_cache->NTDLL(NTSTATUS, NtAllocateVirtualMemory,
      process,
      &remotebuf,
      0,
      &region_size,
      MEM_RESERVE | MEM_COMMIT,
      PAGE_EXECUTE_READWRITE);

    if (NT_SUCCESS(status)) {
      loader_data.image_base =
        static_cast<uint8_t*>(remotebuf) + sizeof(loader_data);
      loader_data.size_of_image = static_cast<DWORD>(length);

      status = g_api_cache->NTDLL(NTSTATUS, NtWriteVirtualMemory,
        process,
        remotebuf,
        &loader_data,
        sizeof(loader_data),
        nullptr);

      if (NT_SUCCESS(status)) {
        status = g_api_cache->NTDLL(NTSTATUS, NtWriteVirtualMemory,
          process,
          loader_data.image_base,
          localbuf,
          length,
          nullptr);
      }

			// zero local buffer - already used it.
			memset(localbuf, 0x00, length);

      if (NT_SUCCESS(status)) {
        auto thread = HANDLE{nullptr};
#ifndef _DEBUG
        constexpr auto thread_create_flags = static_cast<ULONG>(
          THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER);
#else
        constexpr auto thread_create_flags = 0ul;
#endif

        status = g_api_cache->NTDLL(NTSTATUS, NtCreateThreadEx,
          &thread,
          THREAD_ALL_ACCESS,
          nullptr,
          process,
          static_cast<uint8_t*>(loader_data.image_base) + start_offset,
          remotebuf,
          thread_create_flags,
          static_cast<SIZE_T>(0),
          static_cast<SIZE_T>(0),
          static_cast<SIZE_T>(0),
          nullptr);

        if (NT_SUCCESS(status)) {
					// wait until thread exit
					auto exit_code = DWORD{STILL_ACTIVE};
					while (true) {
						g_api_cache->K32(DWORD, WaitForSingleObject, thread, INFINITY);
						g_api_cache->K32(BOOL, GetExitCodeThread, thread, &exit_code);
						if (exit_code != STILL_ACTIVE) {
							break;
						}
					}

					// close thread handle
          g_api_cache->NTDLL(NTSTATUS, NtClose, thread);

					// indicate everything went successful
          result = true;

					// finally clean up the mess
					// read the modified loader data from remote memory 
					// to grab the reallocated buffer so we can zero and free it.
					if (NT_SUCCESS(g_api_cache->NTDLL(NTSTATUS, NtReadVirtualMemory,
																						process,
																						remotebuf,
																						&loader_data,
																						sizeof(loader_data),
																						nullptr))) {
						// check whether we have relocated buffer to zero and free
						if (loader_data.relocated != nullptr) {
							// zero the relocated image before freeing it
							{
								auto zero = std::make_unique<uint8_t[]>(length);

								g_api_cache->NTDLL(NTSTATUS, NtWriteVirtualMemory,
																	 process,
																	 loader_data.relocated,
																	 zero.get(),
																	 length,
																	 nullptr);
							}

							// finally free the relocated image buffer
							{
								auto size = SIZE_T{0};

								g_api_cache->NTDLL(NTSTATUS, NtFreeVirtualMemory,
																	 process,
																	 &loader_data.relocated,
																	 &size,
																	 MEM_RELEASE);
							}
						}
					}
        }

        // zero the memory for security
        {
          auto zero = std::make_unique<uint8_t[]>(length + sizeof(loader_data));

          g_api_cache->NTDLL(NTSTATUS, NtWriteVirtualMemory,
            process,
            remotebuf,
            zero.get(),
            length + sizeof(loader_data),
            nullptr);
        }
      }

      // free the memory
      {
        auto zero = SIZE_T{0};

        g_api_cache->NTDLL(NTSTATUS, NtFreeVirtualMemory,
                           process,
                           remotebuf,
                           &zero,
                           MEM_RELEASE);
      }
    }

    g_api_cache->NTDLL(NTSTATUS, NtClose, process);
  }

  return result;
}
}  // namespace launcher
}  // namespace vape

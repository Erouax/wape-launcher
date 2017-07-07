#include "memsearch.h"
#include <memory>
#include <algorithm>
#include "process.h"
#include "cx_chartbl.h"
#include <mmeapi.h>
#include "pattern_scan.h"
#include "app_main.h"

#define PTR_ADD_OFFSET(Pointer, Offset) \
  ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))

namespace {
constexpr const size_t kPageSize = 0x1000;
constexpr const size_t kBufferSize = kPageSize * 64;  // 2 MB
constexpr const size_t kDisplayBufferSize = (kPageSize * 2 - 1);
constexpr const size_t kDefaultMinimumLength = 4;
}  // namespace

void DoZero(uint8_t* start, size_t len, uint8_t* str, size_t str_len) {
  auto skip = size_t{0};

  while (true) {
    if (skip >= len) {
      break;
    }

    auto ptr = const_cast<uint8_t*>(FindPattern(
      start + skip,
      len - skip,
      str,
      str_len,
      0x00));

    if (!ptr) {
      break;
    }

    memset(ptr, '\0', str_len); // TODO

    const auto distance = ptr - (start + skip);
    skip += distance;
    skip += str_len;
    skip = min(skip, len);
  }
}


void ZeroMemoryContaining(uint8_t* targets,
                          const size_t targets_size,
                          const bool detect_unicode,
                          const ULONG memory_type_mask) {
  auto buffer_size = kBufferSize;
  auto buffer = std::make_unique<uint8_t[]>(buffer_size);

  if (buffer) {
    const auto display_buffer_count = kDisplayBufferSize;
    auto display_buffer = std::make_unique<wchar_t[]>(display_buffer_count + 1);

    if (display_buffer) {
      auto base_address = PVOID{nullptr};
      auto basic_info = MEMORY_BASIC_INFORMATION{nullptr};

      while (NT_SUCCESS(g_api_cache->NTDLL(NTSTATUS, NtQueryVirtualMemory,
                                           NtCurrentProcess(),
                                           base_address,
                                           MemoryBasicInformation,
                                           &basic_info,
                                           sizeof(MEMORY_BASIC_INFORMATION),
                                           nullptr))) {
        auto offset = ULONG_PTR{0};
        auto read_size = SIZE_T{0};

        if (basic_info.State != MEM_COMMIT)
          goto ContinueLoop;
        if ((basic_info.Type & memory_type_mask) == 0)
          goto ContinueLoop;
        if (basic_info.Protect == PAGE_NOACCESS)
          goto ContinueLoop;
        if (basic_info.Protect & PAGE_GUARD)
          goto ContinueLoop;

        read_size = basic_info.RegionSize;

        if (basic_info.RegionSize > buffer_size) {
          if (basic_info.RegionSize <= 16 * 1024 * 1024) {  // 16 MB
            memset(buffer.get(), '\0', buffer_size);

            buffer_size = basic_info.RegionSize;
            buffer = std::make_unique<uint8_t[]>(buffer_size);

            if (!buffer) {
              break;
            }
          } else {
            read_size = buffer_size;
          }
        }

        for (offset = 0;
             offset < basic_info.RegionSize;
             offset += read_size) {
          ULONG_PTR iii;
          UCHAR byte;  // current byte
          UCHAR byte1;  // previous byte
          UCHAR byte2;  // byte before previous byte
          BOOLEAN printable;
          BOOLEAN printable1;
          BOOLEAN printable2;
          ULONG length;

          if (!NT_SUCCESS(g_api_cache->NTDLL(NTSTATUS, NtReadVirtualMemory,
                                             NtCurrentProcess(),
                                             PTR_ADD_OFFSET(base_address,
                                                            offset),
                                             buffer.get(),
                                             read_size,
                                             nullptr))) {
            continue;
          }

          byte1 = 0;
          byte2 = 0;
          printable1 = FALSE;
          printable2 = FALSE;
          length = 0;

          for (iii = 0; iii < read_size; iii++) {
            byte = buffer[iii];
            printable = cx::kCharIsPrintable[byte];

            if (printable2 && printable1 && printable) {
              if (length < display_buffer_count) {
                display_buffer[length] = byte;
              }

              length++;
            } else if (printable2 && printable1 && !printable) {
              if (length >= 3) { // TODO
                goto CreateResult;
              } else if (byte == 0) {
                length = 1;
                display_buffer[0] = byte1;
              } else {
                length = 0;
              }
            } else if (printable2 && !printable1 && printable) {
              if (byte1 == 0) {
                if (length < display_buffer_count) {
                  display_buffer[length] = byte;
                }

                length++;
              }
            } else if (printable2 && !printable1 && !printable) {
              if (length >= 3) { // TODO
                goto CreateResult;
              } else {
                length = 0;
              }
            } else if (!printable2 && printable1 && printable) {
              // length - 1 >= target_length but avoiding underflow
              if (length >= 3 + 1) { // TODO
                length--; // exclude byte1
                goto CreateResult;
              } else {
                length = 2;
                display_buffer[0] = byte1;
                display_buffer[1] = byte;
              }
            } else if (!printable2 && printable1 && !printable) {
              // Nothing
            } else if (!printable2 && !printable1 && printable) {
              if (length < display_buffer_count) {
                display_buffer[length] = byte;
              }

              length++;
            } else if (!printable2 && !printable1 && !printable) {
              // Nothing
            }

            goto AfterCreateResult;

CreateResult:
            {
              auto length_in_bytes = ULONG{length};
              auto bias = ULONG{0};
              auto wide = BOOLEAN{FALSE};

              // determine if string was wide (refer to state table, 4 and 5)
              if (printable1 == printable) {
                wide = TRUE;
                length_in_bytes *= 2;
              }

              // byte1 excluded (refer to state table, 5)
              if (printable) {
                bias = 1;
              }

              const auto start = PTR_ADD_OFFSET(base_address,
                                                iii - bias - length_in_bytes);

              // don't want to wipe our own targets
              if (start >= targets && start <= targets + targets_size) {
                goto EndResult;
              }

              if (!(wide && !detect_unicode)) {
                const auto display_length = min(length,
                                                display_buffer_count)
                                            * sizeof(wchar_t);

                auto string = std::make_unique<wchar_t[]>(display_length + 1);
                memcpy(string.get(), display_buffer.get(), display_length);

                auto found = false;
                auto target = targets;
                auto target_len = size_t{0};
                while (true) {
                  if (target >= targets + targets_size) {
                    break;
                  }
                  target_len = *reinterpret_cast<size_t*>(target);
                  target += sizeof(size_t);

                  {
                    auto wstring = std::make_unique<wchar_t[]>(target_len + 1);
                    for (auto jjj = size_t{0}; jjj < target_len; jjj++) {
                      wstring[jjj] = target[jjj];
                    }

                    if (wcsstr(string.get(), wstring.get())) {
                      found = true;
                    }

                    memset(wstring.get(), 0, target_len * sizeof(wchar_t));

                    if (found) {
                      break;
                    }
                  }

                  target += target_len * sizeof(char);
                  target += sizeof(char);  // \0
                }

                if (found) {
                  if (wide) {
                    auto wstring = std::make_unique<wchar_t[]>(target_len);
                    for (auto jjj = 0u; jjj < target_len; jjj++) {
                      wstring[jjj] = target[jjj];
                    }

                    DoZero(
                      reinterpret_cast<uint8_t*>(start),
                      length_in_bytes,
                      reinterpret_cast<uint8_t*>(wstring.get()),
                      target_len * sizeof(wchar_t));

                    memset(wstring.get(), 0, target_len * sizeof(wchar_t));
                  } else {
                    DoZero(
                      reinterpret_cast<uint8_t*>(start),
                      length_in_bytes,
                      target,
                      target_len);
                  }
                }

                memset(string.get(), '\0', display_length);
              }

EndResult:
              length = 0;
            }

AfterCreateResult:
            byte2 = byte1;
            byte1 = byte;
            printable2 = printable1;
            printable1 = printable;
          }
        }

ContinueLoop:
        base_address = PTR_ADD_OFFSET(base_address, basic_info.RegionSize);
      }

      memset(display_buffer.get(), '\0', display_buffer_count + 1);
    }

    memset(buffer.get(), '\0', buffer_size);
  }
}

#undef PTR_ADD_OFFSET

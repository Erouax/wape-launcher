#include "api_cache.h"

namespace {
#define RtlOffsetToPointer(B, O) ((PCHAR)(((PCHAR)(B)) + ((ULONG_PTR)(O))))
#define MAKE_PTR(B, O, T) ((T)RtlOffsetToPointer(B, O))

PIMAGE_NT_HEADERS PeImageNtHeader(PVOID const image_base) {
  auto dos_header = static_cast<PIMAGE_DOS_HEADER>(image_base);
  auto nt_header = PIMAGE_NT_HEADERS{ nullptr };

  if (dos_header->e_magic == IMAGE_DOS_SIGNATURE) {
    nt_header = MAKE_PTR(image_base,
      dos_header->e_lfanew,
      PIMAGE_NT_HEADERS);
    if (nt_header->Signature == IMAGE_NT_SIGNATURE) {
      return nt_header;
    }
  }

  return nullptr;
}

PVOID PeImageDirectoryEntryToData(const PVOID image_base,
  const ULONG directory,
  PDWORD const size) {
  PIMAGE_NT_HEADERS pe;
  if (!((pe = PeImageNtHeader(image_base)))) {
    return nullptr;
  }

  if (!pe->OptionalHeader.DataDirectory[directory].VirtualAddress) {
    return nullptr;
  }

  if (directory >= pe->OptionalHeader.NumberOfRvaAndSizes) {
    return nullptr;
  }

  const auto virtual_addr =
    pe->OptionalHeader.DataDirectory[directory].VirtualAddress;
  if (!virtual_addr)
    return nullptr;

  if (size) {
    *size = pe->OptionalHeader.DataDirectory[directory].Size;
  }

  return RtlOffsetToPointer(image_base, virtual_addr);
}
}  // namespace

DWORD GetModuleSize(const HMODULE image) {
	auto nt_header = PeImageNtHeader(image);
	if (nt_header) {
		return nt_header->OptionalHeader.SizeOfImage;
	}
	return 0;
}

HMODULE GetModuleBase(const uint32_t dll_hash) {
  if (dll_hash != 0) {
#ifdef _WIN64
    auto const peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    auto const peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif

    auto entry = PLDR_DATA_TABLE_ENTRY{ nullptr };
    auto next = peb->Ldr->InMemoryOrderModuleList.Flink;

    while (next != &peb->Ldr->InMemoryOrderModuleList) {
      entry = CONTAINING_RECORD(next,
        LDR_DATA_TABLE_ENTRY,
        InMemoryOrderLinks);

      if (dll_hash == cx::crc32(entry->BaseDllName.Buffer,
        (entry->BaseDllName.Length / sizeof(wchar_t)),
        true)) {
        return reinterpret_cast<HMODULE>(entry->DllBase);
      }

      next = next->Flink;
    }
  }

  return nullptr;
}

LPVOID GetProcAddr(const HMODULE module, const uint32_t hash) {
  auto exports_size = 0lu;
  auto exports = static_cast<PIMAGE_EXPORT_DIRECTORY>(
    PeImageDirectoryEntryToData(module,
      IMAGE_DIRECTORY_ENTRY_EXPORT,
      &exports_size));
  if (!exports) {
    return nullptr;
  }

  auto ordinal = -1;
  if (HIWORD(hash) == 0) {
    if (LOWORD(hash) >= exports->Base) {
      ordinal = (LOWORD(hash)) - exports->Base;
    }
  } else {
    auto names = MAKE_PTR(module, exports->AddressOfNames, PDWORD);
    auto ordinals = MAKE_PTR(module, exports->AddressOfNameOrdinals, PWORD);
    auto counter = exports->NumberOfNames;

    while (counter--) {
      if (hash == cx::crc32(RtlOffsetToPointer(module, *names))) {
        ordinal = *ordinals;
        break;
      }

      names++;
      ordinals++;
    }
  }

  if (ordinal < 0) {
    return nullptr;
  }

  auto functions = MAKE_PTR(module, exports->AddressOfFunctions, PDWORD);
  auto rva = functions[ordinal];
  auto ret = MAKE_PTR(module, rva, ULONG_PTR);

  if ((ret > reinterpret_cast<ULONG_PTR>(exports)) &&
    ((ret - reinterpret_cast<ULONG_PTR>(exports)) < exports_size)) {
    ret = 0;
  }

  return reinterpret_cast<LPVOID>(ret);
}

NameHashTranslator::~NameHashTranslator() {
}

std::wstring
DefaultNameHashTranslator::TranslateHash(const uint32_t hash) const {
  switch (hash) {
  case kKernel32:		return wstrenc(L"kernel32.dll");
	case kKernelBase: return wstrenc(L"kernelbase.dll");
  case kNtdll:			return wstrenc(L"ntdll.dll");
  case kUser32:			return wstrenc(L"user32.dll");
  case kJvm:				return wstrenc(L"jvm.dll");
  default:
    return {0};
  }
}

ApiCache::ApiCache(std::unique_ptr<NameHashTranslator> translator)
  : translator_(std::move(translator))
  , heap_(K32(HANDLE, GetProcessHeap)) {
}

std::unique_ptr<ModuleInfo>
ApiCache::LoadLib(const wchar_t* lib_name, const uint32_t lib_hash) {
  auto module = GetModuleBase(lib_hash);

  if (!module) {
    std::wstring _;
    const wchar_t* module_name;
    size_t module_name_length;

    if (lib_name) {
      module_name = lib_name;
      module_name_length = wcslen(module_name);
    } else {
      _ = translator_->TranslateHash(lib_hash);
      if (_.empty()) {
        return nullptr;
      }
      module_name = _.c_str();
      module_name_length = _.length();
    }

    auto uncide_module_name = UNICODE_STRING{};
    uncide_module_name.Buffer =
      const_cast<PWCHAR>(module_name);
    uncide_module_name.Length =
      static_cast<USHORT>(module_name_length) * sizeof(wchar_t);
    uncide_module_name.MaximumLength
      = (uncide_module_name.Length + 1) * sizeof(wchar_t);

    const auto status = NTDLL(NTSTATUS, LdrLoadDll,
      nullptr,
      nullptr,
      &uncide_module_name,
      &module);
    if (!NT_SUCCESS(status)) {
      return nullptr;
    }
  }

  auto exports_size = 0lu;
  auto exports = static_cast<PIMAGE_EXPORT_DIRECTORY>(
    PeImageDirectoryEntryToData(module,
      IMAGE_DIRECTORY_ENTRY_EXPORT,
      &exports_size));
  if (!exports) {
    return nullptr;
  }

  auto module_info = std::make_unique<ModuleInfo>();
  module_info->module = module;
  module_info->exports_info.exports = exports;
  module_info->exports_info.size = exports_size;
  return module_info;
}

LPVOID ApiCache::GetForwardedExport(PCCH forward) {
  if (!forward) {
    return nullptr;
  }

  auto function = const_cast<PCHAR>(strchr(forward, '.'));
  if (!function) {
    return nullptr;
  }
  ++function;

  // extension to append
  const auto ext = strenc("DLL");

  // compute size of wide string conversion
  const auto needed = K32(int, MultiByteToWideChar,
    CP_UTF8,
    0,
    function,
    function - forward,
    nullptr,
    0);

  // allocate memory to hold the converted string
  auto dll_name = NTDLL(wchar_t*, RtlAllocateHeap,
    heap_,
    HEAP_ZERO_MEMORY,
    needed + (ext.length() * sizeof(wchar_t)) + 1);
  if (!dll_name) {
    return nullptr;
  }

  // perform the conversion
  K32(int, MultiByteToWideChar,
    CP_UTF8,
    0,
    function,
    function - forward,
    dll_name,
    needed);

  // append extension
  memcpy(dll_name + needed, ext.data(), ext.length() * sizeof(wchar_t));

  // computer hash
  const auto dll_hash = cx::crc32(dll_name, needed + ext.length(), true);

  if (*function == '#') {
    const auto ordinal = atoi(++function);
    const auto proc = GetProcAddress(dll_name, dll_hash, ordinal);
    NTDLL(BOOLEAN, RtlFreeHeap, heap_, 0, dll_name);
    return proc;
  }

  auto proc_hash = cx::crc32(function);
  const auto proc = GetProcAddress(dll_name, dll_hash, proc_hash);
  NTDLL(BOOLEAN, RtlFreeHeap, heap_, 0, dll_name);
  return proc;
}

LPVOID ApiCache::GetProcAddressFromModuleInfo(ModuleInfo* info,
                                              uint32_t hash) {
  auto module = info->module;
  auto exports = info->exports_info.exports;
  auto exports_size = info->exports_info.size;

  auto ordinal = -1;
  if (HIWORD(hash) == 0) {
    if (LOWORD(hash) >= exports->Base) {
      ordinal = (LOWORD(hash)) - exports->Base;
    }
  } else {
    auto names = MAKE_PTR(module, exports->AddressOfNames, PDWORD);
    auto ordinals = MAKE_PTR(module, exports->AddressOfNameOrdinals, PWORD);
    auto counter = exports->NumberOfNames;

    while (counter--) {
      const auto name = RtlOffsetToPointer(module, *names);
      if (hash == cx::crc32(name)) {
        ordinal = *ordinals;
        break;
      }

      names++;
      ordinals++;
    }
  }

  if (ordinal < 0) {
    return nullptr;
  }

  auto functions = MAKE_PTR(module, exports->AddressOfFunctions, PDWORD);
  auto rva = functions[ordinal];
  auto ret = MAKE_PTR(module, rva, ULONG_PTR);

  if ((ret > reinterpret_cast<ULONG_PTR>(exports)) &&
      ((ret - reinterpret_cast<ULONG_PTR>(exports)) < exports_size)) {
    ret = reinterpret_cast<ULONG_PTR>(GetForwardedExport(
      reinterpret_cast<PCCH>(ret)));
  }

  return reinterpret_cast<LPVOID>(ret);
}

__forceinline LPVOID
ApiCache::GetProcAddress(const wchar_t* lib_name,
                         uint32_t lib_hash,
                         const uint32_t proc_hash) {
  auto module_info_it = module_cache_.find(lib_hash);
  if (module_info_it == module_cache_.end()) {
    auto module_info = LoadLib(lib_name, lib_hash);

    if (module_info) {
      auto module_info_ptr = module_info.get();
      module_cache_.insert({ lib_hash, std::move(module_info) });

      auto proc = GetProcAddressFromModuleInfo(module_info_ptr, proc_hash);
      if (proc) {
        module_info_ptr->proc_cache.insert({ proc_hash, proc });
      }
      return proc;
    }
  } else {
    auto& module_info = module_info_it->second;
    auto& proc_cache = module_info->proc_cache;

    auto proc_it = proc_cache.find(proc_hash);
    if (proc_it == proc_cache.end()) {
      auto proc = GetProcAddressFromModuleInfo(module_info.get(), proc_hash);
      if (proc) {
        proc_cache.insert({ proc_hash, proc });
      }
      return proc;
    } else {
      return proc_it->second;
    }
  }

  return nullptr;
}

#undef RtlOffsetToPointer
#undef MAKE_PTR

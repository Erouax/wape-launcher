#pragma once
#include <memory>
#include <unordered_map>
#include "global.h"
#include "cx_crc32.h"
#include "cx_strenc.h"

// Always loaded
enum : uint32_t {
  kKernel32 = cx::crc32("kernel32.dll"),
	kKernelBase = cx::crc32("kernelbase.dll"),
  kNtdll = cx::crc32("ntdll.dll"),
  kUser32 = cx::crc32("user32.dll"),
  kJvm = cx::crc32("jvm.dll")
};

#define K32(R, F, ...) Call<kKernel32, cx::crc32(#F), R, true>(__VA_ARGS__)
#define NTDLL(R, F, ...) Call<kNtdll, cx::crc32(#F), R, true>(__VA_ARGS__)
#define U32(R, F, ...) Call<kUser32, cx::crc32(#F), R, false>(__VA_ARGS__)
#define JVM(R, F, ...) Call<kJvm, ::cx::crc32(#F), R, true>(__VA_ARGS__)

#define FP(F) decltype(&F)
#define CFP(F) reinterpret_cast<FP(F)>

DWORD GetModuleSize(const HMODULE image);
HMODULE GetModuleBase(const uint32_t dll_hash);
// NOTE: doesn't support forwards
LPVOID GetProcAddr(const HMODULE module, const uint32_t proc_hash);

struct ModuleInfo {
  HMODULE module;
  struct {
    PIMAGE_EXPORT_DIRECTORY exports;
    DWORD size;
  } exports_info;
  std::unordered_map<uint32_t, LPVOID> proc_cache;
};

class NameHashTranslator {
 public:
  virtual ~NameHashTranslator() = 0;
  virtual std::wstring TranslateHash(const uint32_t hash) const = 0;
};

class DefaultNameHashTranslator : public NameHashTranslator {
public:
  std::wstring TranslateHash(const uint32_t hash) const override;
};

class ApiCache {
 public:
  explicit ApiCache(std::unique_ptr<NameHashTranslator> translator =
    std::unique_ptr<NameHashTranslator>(
      std::make_unique<DefaultNameHashTranslator>()));

	template<uint32_t LibHash, uint32_t ProcHash,
					 typename ReturnT, bool FailOnDetour, typename... Args>
		__forceinline ReturnT Call(Args... args) {
		typedef ReturnT(WINAPI *fn)(Args...);
		auto function = LPVOID{nullptr};
		if (LibHash == kKernel32) {
			function = GetProcAddress(nullptr, kKernelBase, ProcHash);
			if (!function) {
				function = GetProcAddress(nullptr, kKernel32, ProcHash);
			}
		} else {
			function = GetProcAddress(nullptr, LibHash, ProcHash);
		}
#if 1
		// quit/fastfail on detour detecion
		if (function && FailOnDetour) {
			uint8_t buffer[6] = {0};
			memcpy(buffer, function, sizeof(buffer));
			const auto bytes = strenc("\xFF\x25\x00\x00\x00\x00");
			if (!memcmp(buffer, bytes.data(), min(sizeof(buffer), bytes.length()))) {
				const auto addr = GetProcAddress(nullptr, kNtdll, 0x94FCB0C0);
				reinterpret_cast<decltype(&NtTerminateProcess)>(addr)(NtCurrentProcess(), STATUS_SUCCESS);
				__fastfail(0);
			}
		}
#endif
		return reinterpret_cast<fn>(function)(args...);
	}

  HANDLE Heap() const { return heap_; }

 private:
  LPVOID GetProcAddress(const wchar_t* lib_name,
                        uint32_t lib_hash,
                        const uint32_t proc_hash);
  std::unique_ptr<ModuleInfo> LoadLib(const wchar_t* lib_name,
                                      const uint32_t lib_hash);
  LPVOID GetForwardedExport(PCCH forward);
  LPVOID GetProcAddressFromModuleInfo(ModuleInfo* info,
                                      uint32_t hash);

 private:
  std::unordered_map<uint32_t, std::unique_ptr<ModuleInfo>> module_cache_;
  const std::unique_ptr<NameHashTranslator> translator_;
  const HANDLE heap_;
};

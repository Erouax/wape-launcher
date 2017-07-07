#include <iostream>
#include "winheaders.h"
#include "api_cache.h"
#include "driver.h"
#include "string.h"
#include "cx_obf_addr.h"
#include "app_main.h"
#include "process.h"

#define ANTI_DEBUG
#define PRODUCTION

#if !defined(ANTI_DEBUG) || !defined(PRODUCTION)
#pragma message("WARNING: You sure you want to compile without ANTI_DEBUG || PRODUCTION flag?!")
#pragma message("WARNING: You sure you want to compile without ANTI_DEBUG || PRODUCTION flag?!")
#pragma message("WARNING: You sure you want to compile without ANTI_DEBUG || PRODUCTION flag?!")
#endif

ApiCache* g_api_cache = nullptr;
HINSTANCE g_dll_inst = nullptr;

#pragma region Anti Debug
#ifdef ANTI_DEBUG
namespace {
DWORD g_start_time = 0;
uint8_t g_debug_self = 0;

EXTERN_C extern bool IsInsideVmWare();

bool CheckIsInsideVmWare() {
  __try {
    if (IsInsideVmWare()) {
      return true;
    } else {
      return false;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

struct IsLessThanWin7 {
  __forceinline IsLessThanWin7() {}
  __forceinline bool operator()() const {
    OSVERSIONINFOW osvi = { 0 };
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);

    if (ApiCache().K32(BOOL, GetVersionExW, &osvi)) {
      if (osvi.dwMajorVersion < HIBYTE(_WIN32_WINNT_WIN7) &&
        osvi.dwMinorVersion < LOBYTE(_WIN32_WINNT_WIN7)) {
        return !true;
      } else {
        return !false;
      }
    }

    return !true;
  }
};

constexpr const uint32_t kDbgHelp = cx::crc32("dbghlp.dll");

struct CheckDbgHelp {
  __forceinline CheckDbgHelp() {}
  __forceinline bool operator()() const {
    return !(GetModuleBase(kDbgHelp) != nullptr);
  }
};

struct GetBeingDebugged {
  __forceinline GetBeingDebugged() {}
  __forceinline bool operator()() const {
#ifdef _WIN64
    auto const peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    auto const peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif

    return !peb->BeingDebugged;
  }
};

struct CheckNtGlobalFlag {
  __forceinline CheckNtGlobalFlag() {}
  __forceinline bool operator()() const {
#ifdef _WIN64
    auto const peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    auto const peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif

		const bool debugger_present = peb->NtGlobalFlag & 0x70;
		return !debugger_present;
  }
};

bool IsAtleastVista() {
	OSVERSIONINFOW osvi = {0};
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);

	if (ApiCache().K32(BOOL, GetVersionExW, &osvi)) {
		if (osvi.dwMajorVersion >= HIBYTE(_WIN32_WINNT_VISTA)) {
			return true;
		}
	}

	return false;
}

struct CheckHeapFlags {
  __forceinline CheckHeapFlags() {}
  __forceinline bool operator()() const {
		uint8_t flags_offset;
		uint8_t force_flags_offset;
		auto const is_atleast_vista = IsAtleastVista();

#ifdef _WIN64
    auto const peb = reinterpret_cast<PPEB>(__readgsqword(0x60));

		if (is_atleast_vista) {
			flags_offset = 0x70;
			force_flags_offset = 0x74;
		} else {
			flags_offset = 0x14;
			force_flags_offset = 0x18;
		}
#else
    auto const peb = reinterpret_cast<PPEB>(__readfsdword(0x30));

		if (is_atleast_vista) {
			flags_offset = 0x40;
			force_flags_offset = 0x44;
		} else {
			flags_offset = 0x0C;
			force_flags_offset = 0x10;
		}
#endif

#if 0
    const auto flags =
			*(static_cast<PULONG32>(peb->ProcessHeap) + flags_offset);

    const auto force_flags =
			*(static_cast<PULONG32>(peb->ProcessHeap) + force_flags_offset);

    return !((flags & HEAP_GROWABLE) != 0 || force_flags != 0);
#else
		const auto force_flags =
			*(static_cast<PULONG32>(peb->ProcessHeap) + force_flags_offset);

		return !(force_flags != 0);
#endif
  }
};

struct CheckRemoteDebugger {
  __forceinline CheckRemoteDebugger() {}
  __forceinline bool operator()() const {
    auto present = BOOL{0};
    ApiCache().K32(BOOL, CheckRemoteDebuggerPresent,
      NtCurrentProcess(), &present);
    return !present;
  }
};

__forceinline void CloseInvalidHandle() {
  const auto handle = reinterpret_cast<HANDLE>(0x8000);
  ApiCache{}.NTDLL(NTSTATUS, NtClose, handle);
}

struct CheckCloseHandle {
  __forceinline CheckCloseHandle() {}
  __forceinline bool operator()() const {
    __try {
      CloseInvalidHandle();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      return !true;
    }

    return !false;
  }
};

struct CheckDebugPrivilege {
  __forceinline CheckDebugPrivilege() {}
  __forceinline bool operator()() const {
    ApiCache api;
    const auto csr_pid = api.NTDLL(HANDLE, CsrGetProcessId);

    auto handle = HANDLE{ nullptr };
    auto obj_attr = CLIENT_ID{ csr_pid, nullptr };
    auto result = NT_SUCCESS(api.NTDLL(NTSTATUS, NtOpenProcess,
      &handle,
      PROCESS_ALL_ACCESS,
      nullptr,
      &obj_attr));

    if (result) {
      api.NTDLL(NTSTATUS, NtClose, handle);
    }

    return !result;
  }
};

__forceinline DWORD GetParentProcessId() {
  auto pbi = PROCESS_BASIC_INFORMATION{ 0 };

  if (NT_SUCCESS(ApiCache{}.NTDLL(NTSTATUS, NtQueryInformationProcess,
    NtCurrentProcess(),
    ProcessBasicInformation,
    &pbi,
    sizeof(pbi),
    nullptr))) {
#pragma warning(push)
#pragma warning(disable: 4311)
#pragma warning(disable: 4302)
    return reinterpret_cast<DWORD>(pbi.InheritedFromUniqueProcessId);
#pragma warning(pop)
  }

  return 0;
}

__forceinline DWORD GetExplorerProcessId() {
  ApiCache api;
  return api.U32(DWORD, GetWindowThreadProcessId,
    api.U32(HWND, GetShellWindow),
    nullptr);
}

struct CheckIsParentExplorer {
  __forceinline CheckIsParentExplorer() {}
  __forceinline bool operator()() const {
    return !(GetParentProcessId() == GetExplorerProcessId());
  }
};

__forceinline bool DebugSelf() {
  ApiCache api;
  auto de = DEBUG_EVENT{ 0 };
  auto pi = PROCESS_INFORMATION{ nullptr };
  auto si = STARTUPINFOW{ 0 };

  api.K32(VOID, GetStartupInfoW, &si);

  api.K32(BOOL, CreateProcessW,
    nullptr,
    api.K32(LPWSTR, GetCommandLineW),
    nullptr,
    nullptr,
    FALSE,
    DEBUG_PROCESS,
    nullptr,
    nullptr,
    &si,
    &pi);

  api.K32(BOOL, ContinueDebugEvent,
    pi.dwProcessId,
    pi.dwThreadId,
    static_cast<DWORD>(DBG_CONTINUE));

  api.K32(BOOL, WaitForDebugEvent,
    &de,
    INFINITE);

  return true;
}

__forceinline void OutputInvalidDebugString() {
  ApiCache{}.K32(void, OutputDebugStringA, charenc(
    "%s%s%s%s%s%s%s%s%s%s%s"
    "%s%s%s%s%s%s%s%s%s%s%s%s%s"
    "%s%s%s%s%s%s%s%s%s%s%s%s%s"
    "%s%s%s%s%s%s%s%s%s%s%s%s%s"));
}

struct CheckDebugString {
  __forceinline CheckDebugString() {}
  __forceinline bool operator()() const {
    __try {
      OutputInvalidDebugString();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      return !true;
    }

    return !false;
  }
};

__forceinline uint32_t GetDebugRegisters() {
  auto ctx = CONTEXT{ 0 };
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
  if (!ApiCache{}.K32(BOOL, GetThreadContext, NtCurrentThread(), &ctx)) {
    return 1337;
  }

  auto iii = uint32_t{ 0 };
  if (ctx.Dr0 != 0) iii++;
  if (ctx.Dr1 != 0) iii++;
  if (ctx.Dr2 != 0) iii++;
  if (ctx.Dr3 != 0) iii++;

  return iii;
}

struct CheckDebugRegisters {
  __forceinline CheckDebugRegisters() {}
  __forceinline bool operator()() const {
    return !(GetDebugRegisters() > 0);
  }
};

BOOLEAN IsThreadHiddenFromDebugger() {
  auto result = BOOLEAN{ FALSE };
  if (!NT_SUCCESS(ApiCache{}.NTDLL(NTSTATUS, NtQueryInformationThread,
    NtCurrentThread(),
    ThreadHideFromDebugger,
    &result,
    sizeof(result),
    nullptr))) {
    return 137;
  }
  return result;
}

struct CheckHideThreadFromDebugger {
  __forceinline CheckHideThreadFromDebugger() {}
  __forceinline bool operator()() const {
    ApiCache api;
    auto check = BOOLEAN{ FALSE };

    // Must fail - invalid param
    if (NT_SUCCESS(api.NTDLL(NTSTATUS, NtSetInformationThread,
      NtCurrentThread(),
      ThreadHideFromDebugger,
      &check,
      sizeof(ULONG)))) {
      return !TRUE;
    }

    // Must fail - invalid handle
    if (NT_SUCCESS(api.NTDLL(NTSTATUS, NtSetInformationThread,
      reinterpret_cast<HANDLE>(0xFFFFF),
      ThreadHideFromDebugger,
      nullptr,
      0))) {
      return !TRUE;
    }

    if (!NT_SUCCESS(api.NTDLL(NTSTATUS, NtSetInformationThread,
      NtCurrentThread(),
      ThreadHideFromDebugger,
      0,
      0))) {
      return !TRUE;
    }

    if (IsThreadHiddenFromDebugger()) {
      return !FALSE;
    } else {
      return !TRUE;
    }
  }
};

__forceinline bool CheckDebugObjectHandle() {
  ApiCache api;
  auto debug_obj = HANDLE{ nullptr };

  auto status = api.NTDLL(NTSTATUS, NtQueryInformationProcess,
    NtCurrentProcess(),
    ProcessDebugObjectHandle,
    &debug_obj,
    sizeof(debug_obj),
    nullptr);

  if (status == STATUS_PORT_NOT_SET) {
    api.NTDLL(NTSTATUS, NtClose, debug_obj);
    return false;
  }

  if (!NT_SUCCESS(status)) {
    api.NTDLL(NTSTATUS, NtClose, debug_obj);
    return true;
  }

  api.NTDLL(NTSTATUS, NtClose, debug_obj);
  if (debug_obj) {
    return true;
  } else {
    return false;
  }
}

__forceinline bool CheckDebugObjectCount() {
  ApiCache api;
  auto debug_obj = HANDLE{ nullptr };
  auto obj_attr = OBJECT_ATTRIBUTES{};
  InitializeObjectAttributes(&obj_attr, nullptr, 0, nullptr, nullptr);

  if (!NT_SUCCESS(api.NTDLL(NTSTATUS, NtCreateDebugObject,
    &debug_obj,
    DEBUG_ALL_ACCESS,
    &obj_attr,
    0))) {
    return true;
  }

  auto length = ULONG{ 0 };
  if (api.NTDLL(NTSTATUS, NtQueryObject,
    debug_obj,
    ObjectTypeInformation,
    nullptr,
    nullptr,
    &length) != STATUS_INFO_LENGTH_MISMATCH) {
    api.NTDLL(NTSTATUS, NtRemoveProcessDebug, NtCurrentProcess(), debug_obj);
    api.NTDLL(NTSTATUS, NtClose, debug_obj);
    return true;
  }

  auto buffer = reinterpret_cast<POBJECT_TYPE_INFORMATION>(malloc(length));
  if (!buffer) {
    api.NTDLL(NTSTATUS, NtRemoveProcessDebug, NtCurrentProcess(), debug_obj);
    api.NTDLL(NTSTATUS, NtClose, debug_obj);
    return true;
  }

  if (!NT_SUCCESS(api.NTDLL(NTSTATUS, NtQueryObject,
    debug_obj,
    ObjectTypeInformation,
    buffer,
    length,
    nullptr))) {
    free(buffer);
    api.NTDLL(NTSTATUS, NtRemoveProcessDebug, NtCurrentProcess(), debug_obj);
    api.NTDLL(NTSTATUS, NtClose, debug_obj);
    return true;
  }

  const auto result = buffer->TotalNumberOfObjects <= 1;

  free(buffer);
  api.NTDLL(NTSTATUS, NtRemoveProcessDebug, NtCurrentProcess(), debug_obj);
  api.NTDLL(NTSTATUS, NtClose, debug_obj);
  return result;
}

struct CheckDebugObject {
  __forceinline CheckDebugObject() {}
  __forceinline bool operator()() const {
    if (CheckDebugObjectHandle() /*|| CheckDebugObjectCount()*/) {
      return !true;
    }
    return !false;
  }
};

struct CheckProcessDebugFlags {
  __forceinline CheckProcessDebugFlags() {}
  __forceinline bool operator()() const {
    auto no_debug_inherit = DWORD{0};
    auto status = ApiCache{}.NTDLL(NTSTATUS, NtQueryInformationProcess,
      NtCurrentProcess(),
      ProcessDebugFlags,
      &no_debug_inherit,
      sizeof(no_debug_inherit),
      nullptr);
    if (!NT_SUCCESS(status)) {
      return !true;
    }

    if (no_debug_inherit == FALSE) {
      return !true;
    } else {
      return !false;
    }
  }
};

bool CheckWindowClasses() {
	constexpr const auto kOlly = cx::crc32("OLLYDBG");
	constexpr const auto kWinDbg = cx::crc32("WinDbgFrameClass");
	constexpr const auto kProcMon = cx::crc32("PROCMON_WINDOW_CLASS");
	constexpr const auto kZetaDebug = cx::crc32("Zeta Debugger");
	constexpr const auto kRockDebug = cx::crc32("Rock Debugger");
	constexpr const auto kObsidianDebug = cx::crc32("ObsidianGUI");
	constexpr const auto kImmunityDebug = cx::crc32("ID");
	constexpr const auto kIdaWindow = cx::crc32("idawindow");
	constexpr const auto kIdaView = cx::crc32("idaview");
	constexpr const auto kNavBox = cx::crc32("tnavbox");
	constexpr const auto kTgrZoom = cx::crc32("tgrzoom");

	return AnyWindowClassRunning({
		kOlly, kWinDbg, kProcMon,
		kZetaDebug, kRockDebug, kObsidianDebug,
		kImmunityDebug, kIdaWindow, kIdaView,
		kNavBox, kTgrZoom
	});
}

bool CheckProcesses() {
	constexpr const auto kOlly = cx::crc32("ollydbg.exe");
	constexpr const auto kIdag = cx::crc32("idag.exe");
	constexpr const auto kIdag64 = cx::crc32("idag64.exe");
	constexpr const auto kIdaq = cx::crc32("idaq.exe");
	constexpr const auto kIdaq64 = cx::crc32("idaq64.exe");
	constexpr const auto kIdaw = cx::crc32("idaw.exe");
	constexpr const auto kIdaw64 = cx::crc32("idaw64.exe");
	constexpr const auto kScylla = cx::crc32("scylla.exe");
	constexpr const auto kScylla64 = cx::crc32("scylla_x64.exe");
	constexpr const auto kScally86 = cx::crc32("scylla_x86.exe");
	constexpr const auto kProtectId = cx::crc32("protection_id.exe");
	constexpr const auto kX64dbg = cx::crc32("x64dbg.exe");
	constexpr const auto kX32dbg = cx::crc32("x32dbg.exe");
	constexpr const auto kWindbg = cx::crc32("windbg.exe");
	constexpr const auto kReshacker = cx::crc32("reshacker.exe");
	constexpr const auto kImportRec = cx::crc32("ImportREC.exe");
	constexpr const auto kImmunityDebug = cx::crc32("IMMUNITYDEBUGGER.EXE");

	return AnyProcessRunning({
		kOlly, kIdag, kIdag64,
		kIdaw, kIdaw64, kScylla,
		kScylla64, kScally86, kProtectId,
		kX64dbg, kX32dbg, kWindbg,
		kReshacker, kImportRec, kImmunityDebug,
		kIdaq, kIdaq64
	});
}

bool CheckDrivers() {
  constexpr const auto kVBoxVideo = cx::crc32("vboxvideo.sys");
  constexpr const auto kVBoxGuest = cx::crc32("vboxguest.sys");
  constexpr const auto kVBoxMouse = cx::crc32("vboxmouse.sys");
	constexpr const auto kVmwareMouse = cx::crc32("vmmouse.sys");
	constexpr const auto kVmwareShare = cx::crc32("vmhgfs.sys");

  std::vector<std::wstring> drivers;
  if (GetLoadedDrivers(&drivers)) {
    for (const auto& driver : drivers) {
      switch (cx::crc32(driver.data(), driver.length(), true)) {
      case kVBoxVideo:
      case kVBoxGuest:
      case kVBoxMouse:
			case kVmwareMouse:
			case kVmwareShare:
        return true;
      default:
        break;
      }
      if (begins_with(driver, wstrenc(L"PROCMON"))) {
        return true;
      }
    }
  }

  return false;
}

bool IsDebuggingToolRunning() {
#ifdef PRODUCTION
  if (CheckWindowClasses()) {
		return true;
  }
	if (CheckProcesses()) {
		return true;
	}
  if (CheckDrivers()) {
    return true;
  }
  if (CheckIsInsideVmWare()) {
    return true;
  }
#endif
	return false;
}

struct CheckDebuggingTools {
  __forceinline CheckDebuggingTools() {}
  __forceinline bool operator()() const {
    return !(IsDebuggingToolRunning());
  }
};

__forceinline bool CheckTickCount() {
  if (g_start_time == 0) {
    return true;
  }
  const auto now = ApiCache{}.K32(DWORD, GetTickCount);
  return (now - g_start_time) > 315;
}

namespace {
  struct InitializeGlobalApiCache {
    __forceinline InitializeGlobalApiCache() {}
    __forceinline bool operator()() const {
      if (!g_api_cache) {
        g_api_cache = new ApiCache;
      }
      return CheckNtGlobalFlag{}();
    }
  };
}  // namespace

__forceinline bool CheckDebuggerPresent() {
  auto status = bool{ false };

  status |= !(IsLessThanWin7{})();

  ApiCache api;
  g_start_time = api.K32(DWORD, GetTickCount);
  status |= !(CheckHeapFlags{})();
  status |= !(GetBeingDebugged{})();
  status |= !(CheckNtGlobalFlag{})();
  status |= !(CheckRemoteDebugger{})();
  status |= !(CheckDebugString{})();
  status |= !(CheckDebugPrivilege{})();
  status |= !(CheckDebugRegisters{})();
  status |= !(CheckCloseHandle{})();
  status |= !(CheckDbgHelp{})();
  status |= !(CheckIsParentExplorer{})();
  status |= !(CheckDebuggingTools{})();
  status |= !(CheckDebugObject{})();
  status |= !(CheckProcessDebugFlags{})();
  status |= CheckTickCount();

  return status;
}

VOID NTAPI TlsCallback00(PVOID, DWORD, PVOID) {
  if (!(IsLessThanWin7{})()) {
    ApiCache{}.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

VOID NTAPI TlsCallback01(PVOID, DWORD, PVOID) {
	ApiCache api;
  g_start_time = api.K32(DWORD, GetTickCount);

  if (!g_debug_self) {
    g_debug_self = 1;
    DebugSelf();
  }
}

VOID NTAPI TlsCallback02(PVOID, DWORD, PVOID) {
  if (!(CheckHeapFlags{})()) {
    ApiCache{}.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

VOID NTAPI TlsCallback03(PVOID, DWORD, PVOID) {
  if (!(GetBeingDebugged{})()) {
    ApiCache{}.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

VOID NTAPI TlsCallback04(PVOID, DWORD, PVOID) {
  if (!(InitializeGlobalApiCache{})()) {
    ApiCache{}.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

VOID NTAPI TlsCallback05(PVOID, DWORD, PVOID) {
  if (!(CheckRemoteDebugger{})()) {
    ApiCache{}.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

VOID NTAPI TlsCallback06(PVOID, DWORD, PVOID) {
  if (!(CheckDebugString{})()) {
    ApiCache{}.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

VOID NTAPI TlsCallback07(PVOID, DWORD, PVOID) {
  if (!(CheckDebugPrivilege{})()) {
    ApiCache{}.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

VOID NTAPI TlsCallback08(PVOID, DWORD, PVOID) {
  ApiCache api;
  if (!(CheckDebugRegisters{})()) {
    api.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

VOID NTAPI TlsCallback09(PVOID, DWORD, PVOID) {
  if (!(CheckCloseHandle{})()) {
    ApiCache{}.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

VOID NTAPI TlsCallback10(PVOID, DWORD, PVOID) {
  if (!(CheckDbgHelp{})()) {
    ApiCache{}.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

VOID NTAPI TlsCallback11(PVOID, DWORD, PVOID) {
  if (!(CheckHideThreadFromDebugger{})()) {
    ApiCache{}.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

VOID NTAPI TlsCallback12(PVOID, DWORD, PVOID) {
  if (!(CheckIsParentExplorer{})()) {
    ApiCache{}.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

VOID NTAPI TlsCallback13(PVOID, DWORD, PVOID) {
  if (!(CheckDebuggingTools{})()) {
    ApiCache{}.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

VOID NTAPI TlsCallback14(PVOID, DWORD, PVOID) {
  if (!(CheckDebugObject{})()) {
    ApiCache{}.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

VOID NTAPI TlsCallback15(PVOID, DWORD, PVOID) {
  if (!(CheckProcessDebugFlags{})()) {
    ApiCache{}.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

VOID NTAPI TlsCallback16(PVOID, DWORD, PVOID) {
	if (CheckTickCount()) {
    ApiCache{}.NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
}

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:_tls_callback00")
#pragma const_seg(".CRT$XLB")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback00 = TlsCallback00;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback01")
#pragma const_seg(".CRT$XLC")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback01 = TlsCallback01;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback02")
#pragma const_seg(".CRT$XLD")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback02 = TlsCallback02;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback03")
#pragma const_seg(".CRT$XLE")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback03 = TlsCallback03;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback04")
#pragma const_seg(".CRT$XLF")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback04 = TlsCallback04;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback05")
#pragma const_seg(".CRT$XLG")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback05 = TlsCallback05;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback06")
#pragma const_seg(".CRT$XLH")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback06 = TlsCallback06;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback07")
#pragma const_seg(".CRT$XLI")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback07 = TlsCallback07;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback08")
#pragma const_seg(".CRT$XLJ")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback08 = TlsCallback08;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback09")
#pragma const_seg(".CRT$XLK")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback09 = TlsCallback09;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback10")
#pragma const_seg(".CRT$XLL")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback10 = TlsCallback10;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback11")
#pragma const_seg(".CRT$XLM")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback11 = TlsCallback11;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback12")
#pragma const_seg(".CRT$XLN")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback12 = TlsCallback12;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback13")
#pragma const_seg(".CRT$XLO")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback13 = TlsCallback13;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback14")
#pragma const_seg(".CRT$XLP")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback14 = TlsCallback14;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback15")
#pragma const_seg(".CRT$XLQ")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback15 = TlsCallback15;
#pragma const_seg()
#pragma comment(linker, "/INCLUDE:_tls_callback16")
#pragma const_seg(".CRT$XLR")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback16 = TlsCallback16;
#pragma const_seg()
}  // namespace
#endif
#pragma endregion

#pragma region Entry Point
NTSTATUS NTAPI MainWrapper(PVOID thread_param) {
#ifdef ANTI_DEBUG
  if (CheckTickCount()) {
    g_api_cache->NTDLL(NTSTATUS, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }

  if (!IsThreadHiddenFromDebugger()) {
    g_api_cache->NTDLL(DWORD, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }

  if (CheckDebuggerPresent()) {
    g_api_cache->NTDLL(DWORD, NtTerminateProcess,
      NtCurrentProcess(), static_cast<void*>(nullptr));
    __fastfail(0);
  }
#else
  g_api_cache = new ApiCache;
#endif

  wape::launcher::AppMain();

  delete g_api_cache;
  g_api_cache = nullptr;
  return STATUS_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		g_dll_inst = hinstDLL;
	}
	return TRUE;
}

extern "C" __declspec(dllexport)
void CALLBACK EntryPoint() {
#ifndef _DEBUG
  constexpr auto thread_create_flags = static_cast<ULONG>(THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER);
#else
  constexpr auto thread_create_flags = 0ul;
#endif

  ApiCache api;
  auto thread_handle = INVALID_HANDLE_VALUE;
  const auto app_main = cx::MakeObfuscatedAddress(MainWrapper, 0x31337);

  const auto status = api.NTDLL(NTSTATUS, NtCreateThreadEx,
    &thread_handle,
    THREAD_ALL_ACCESS,
    nullptr,
    NtCurrentProcess(),
    app_main.original(),
    nullptr,
    thread_create_flags,
    static_cast<SIZE_T>(0),
    static_cast<SIZE_T>(0),
    static_cast<SIZE_T>(0),
    nullptr);

  if (NT_SUCCESS(status)) {
    api.K32(DWORD, WaitForSingleObject, thread_handle, INFINITE);
  }
}
#pragma endregion

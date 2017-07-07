#include "java_thread.h"
#include "pattern_scan.h"
#include "virtual_func.h"

#pragma region Pattern Scanner
namespace {
class JavaThreadPatternScan {
public:
	__declspec(noinline)
  static JavaThread** FindThreadListPtr() {
    const auto pattern = strenc("\x48\x8B\x05\xCC\xCC\xCC\xCC\x40\xB7\x01");
    const auto result = FindPattern(
			reinterpret_cast<const uint8_t*>(GetModule()), module_size_,
      reinterpret_cast<const uint8_t*>(pattern.data()), pattern.length(),
			0xCC);

		if (result) {
			const auto offset = *reinterpret_cast<const uint32_t*>(result + 3);
			const auto target = const_cast<uint8_t*>(result) + 7 + offset;
			return reinterpret_cast<JavaThread**>(target);
		}

		__fastfail(0);
		return nullptr;
  }

	__declspec(noinline)
  static auto FindNextOffset() {
    const auto pattern =
      strenc("\x48\x89\x81\xCC\xCC\xCC\xCC\xFF\x05\xCC\xCC\xCC\xCC");
    const auto result = FindPattern(
			reinterpret_cast<const uint8_t*>(GetModule()), module_size_,
			reinterpret_cast<const uint8_t*>(pattern.data()), pattern.length(),
			0xCC);

		if (result) {
			return *reinterpret_cast<const uint32_t*>(result + 3);
		}

		__fastfail(0);
		return 0u;
  }

	__declspec(noinline)
  static auto FindJniAttachStateOffset() {
		const auto pattern =
			strenc("\x8B\x8B\xCC\xCC\xCC\xCC\x48\x8D\x05\xCC\xCC\xCC\xCC\x48\x8D\x15\xCC\xCC\xCC\xCC");
		const auto result = FindPattern(
			reinterpret_cast<const uint8_t*>(GetModule()), module_size_,
			reinterpret_cast<const uint8_t*>(pattern.data()), pattern.length(),
			0xCC);

		if (result) {
			return *reinterpret_cast<const uint32_t*>(result + 2);
		}

		__fastfail(0);
		return 0u;
  }

  static auto FindJvmtiAgentThreadVIndex() {
    return 7;  // TODO(x): pattern scan
  }

public:
  static HMODULE GetModule() {
    if (!module_) {
      module_ = GetModuleBase(kJvm);
			module_size_ = GetModuleSize(module_);
    }
    return module_;
  }

public:
  static HMODULE module_;
	static DWORD module_size_;
};

HMODULE JavaThreadPatternScan::module_ = nullptr;
DWORD JavaThreadPatternScan::module_size_ = 0;
}  // namespace
#pragma endregion

bool JavaThread::IsJvmtiAgentThread() const {
  typedef bool(__thiscall* is_jvmti_agent_thread)();
	static auto vtable_idx = 0;
	if (vtable_idx == 0) {
		vtable_idx = JavaThreadPatternScan::FindJvmtiAgentThreadVIndex();
	}
  return GetVirtualFunc<is_jvmti_agent_thread>(this, vtable_idx)();
}

JNIAttachStates JavaThread::JniAttachState() {
	static auto offset = uint32_t{0};
	if (offset == 0) {
		offset = JavaThreadPatternScan::FindJniAttachStateOffset();
	}
  return *reinterpret_cast<JNIAttachStates*>(this + offset);
}

JavaThread* JavaThread::Next() {
  static auto next_offset = uint32_t{0};
	if (next_offset == 0) {
		next_offset = JavaThreadPatternScan::FindNextOffset();
	}
  return *reinterpret_cast<JavaThread**>(this + next_offset);
}

JavaThread* JavaThread::First() {
	static JavaThread** thread_list_ptr = nullptr;
	if (thread_list_ptr == nullptr) {
		thread_list_ptr = JavaThreadPatternScan::FindThreadListPtr();
	}
  return *thread_list_ptr;
}

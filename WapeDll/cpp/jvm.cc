#include "jvm.h"
#include "global.h"
#include "java_thread.h"
#include "pattern_scan.h"

namespace wape {
namespace dll {
bool AttachJvm(AppContext* app_ctx) {
  auto status = g_api_cache->JVM(jint, JNI_GetCreatedJavaVMs,
    &app_ctx->jvm, 1, nullptr);

  if (status == JNI_OK) {
    status = app_ctx->jvm->AttachCurrentThread(
      reinterpret_cast<void**>(&app_ctx->jni), nullptr);

    if (status == JNI_OK) {
      status = app_ctx->jvm->GetEnv(
        reinterpret_cast<void**>(&app_ctx->jvmti), JVMTI_VERSION_1_1);

      if (status == JNI_OK) {
        return true;
      }
    }
  }
  return false;
}

void DetachJvm(AppContext* app_ctx) {
  if (app_ctx->jvm && app_ctx->jni) {
    if (app_ctx->jvmti) {
      app_ctx->jvmti->DisposeEnvironment();
      app_ctx->jvmti = nullptr;
    }

    app_ctx->jvm->DetachCurrentThread();
    app_ctx->jvm = nullptr;
    app_ctx->jni = nullptr;
  }
}

bool IsNativeSessionActive() {
  auto sessions = 0u;
	auto thread = JavaThread::First();

	while (thread != nullptr) {
		const auto jni_attach_state = thread->JniAttachState();

		if (thread->IsJvmtiAgentThread() ||
			(jni_attach_state == _attaching_via_jni ||
			 jni_attach_state == _attached_via_jni)) {
			sessions++;
		}

		thread = thread->Next();
	}

  return sessions > 0;
}

void RunFinalizationAndForceGC(JNIEnv* jni, jvmtiEnv* jvmti) {
	const auto system_klass = jni->FindClass(charenc("java/lang/System"));
	const auto run_finalization_mid = jni->GetStaticMethodID(
		system_klass,
		charenc("runFinalization"),
		charenc("()V"));

  jni->CallStaticVoidMethod(system_klass, run_finalization_mid);
  jni->DeleteLocalRef(system_klass);
  jvmti->ForceGarbageCollection();
}

uint8_t* g_explicit_gc_invokes_concurrent_and_unloads_classes_ptr = nullptr;
uint8_t* ResolveExplicitGCInvokesConcurrentAndUnloadsClassesPtr() {
	const auto jvm_base = GetModuleBase(kJvm);
	const auto jvm_size = GetModuleSize(jvm_base);
	const auto pattern = strenc("\x80\x3D\xCC\xCC\xCC\xCC\xCC\x74\x0D\xC6\x81\xCC\xCC\xCC\xCC\xCC");
	const auto match = FindPattern(
		reinterpret_cast<const uint8_t*>(jvm_base), jvm_size,
		reinterpret_cast<const uint8_t*>(pattern.data()), pattern.length(),
		0xCC);
	if (match) {
		auto offset = *reinterpret_cast<const uint32_t*>(match + 2);
		auto target = match + 7 + offset;
		return const_cast<uint8_t*>(target);
	}
	return nullptr;
}

bool GetExplicitGCInvokesConcurrentAndUnloadsClasses(bool* result) {
	if (!g_explicit_gc_invokes_concurrent_and_unloads_classes_ptr) {
		g_explicit_gc_invokes_concurrent_and_unloads_classes_ptr =
			ResolveExplicitGCInvokesConcurrentAndUnloadsClassesPtr();
	}
	if (g_explicit_gc_invokes_concurrent_and_unloads_classes_ptr) {
		if (result) {
			*result = *g_explicit_gc_invokes_concurrent_and_unloads_classes_ptr;
		}
		return true;
	}
	return false;
}

bool SetExplicitGCInvokesConcurrentAndUnloadsClasses(bool flag) {
	if (!g_explicit_gc_invokes_concurrent_and_unloads_classes_ptr) {
		g_explicit_gc_invokes_concurrent_and_unloads_classes_ptr =
			ResolveExplicitGCInvokesConcurrentAndUnloadsClassesPtr();
	}
	if (g_explicit_gc_invokes_concurrent_and_unloads_classes_ptr) {
		*g_explicit_gc_invokes_concurrent_and_unloads_classes_ptr = flag;
		return true;
	}
	return false;
}
}  // namespace dll
}  // namespace wape

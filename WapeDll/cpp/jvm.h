#pragma once
#include "app_main.h"

namespace wape {
namespace dll {
bool AttachJvm(AppContext* app_context);
void DetachJvm(AppContext* app_context);
bool IsNativeSessionActive();
void RunFinalizationAndForceGC(JNIEnv* jni, jvmtiEnv* jvmti);

bool GetExplicitGCInvokesConcurrentAndUnloadsClasses(bool* result);
bool SetExplicitGCInvokesConcurrentAndUnloadsClasses(bool flag);
}  // namespace dll
}  // namespace wape

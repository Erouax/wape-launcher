#pragma once
#include "global.h"
#include <jni.h>
#include <jvmti.h>

namespace wape {
namespace dll {
struct AppContext {
  HMODULE module_base;
  JavaVM* jvm;
  JNIEnv* jni;
  jvmtiEnv* jvmti;
  HANDLE self_destruct_event;
};

extern AppContext* g_app_ctx;

void AppMain(HMODULE module_base);
}  // namespace dll
}  // namespace wape

#pragma once
#include <jni.h>

namespace wape {
namespace dll {
bool IsMinecraft(JNIEnv* jni);
bool IsForgeAvailable(JNIEnv* jni);
jobject FindMinecraftClassLauncher(JNIEnv* jni);
void RefreshResources(JNIEnv* jni);
}  // namespace dll
}  // namespace wape

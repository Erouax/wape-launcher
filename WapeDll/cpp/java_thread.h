#pragma once
#include "global.h"

// JNI attach states:
enum JNIAttachStates {
  _not_attaching_via_jni = 1,  // thread is not attaching via JNI
  _attaching_via_jni,          // thread is attaching via JNI
  _attached_via_jni            // thread has attached via JNI
};

class JavaThread {
public:
  bool IsJvmtiAgentThread() const;
  JNIAttachStates JniAttachState();

  JavaThread* Next();
  static JavaThread* First();
};

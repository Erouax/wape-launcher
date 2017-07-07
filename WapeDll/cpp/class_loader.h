#pragma once
#include <jni.h>
#include <jvmti.h>
#include <vector>
#include "global.h"

namespace wape {
namespace dll {
#pragma pack(push, 1)
struct EncryptedZipEntryEntry {
  uint32_t name_length;
  uint64_t name_seed;
  uint32_t data_length;
  uint64_t data_seed;
};
#pragma pack(pop)

struct EncryptedJarEntry {
  EncryptedZipEntryEntry header;
  uint8_t* name_ptr;
  uint8_t* data_ptr;
};

constexpr const uint32_t kTerminator = 0xDEADC0DE;
constexpr const EncryptedJarEntry kEmptyEncryptedJarEnty = {
  {kTerminator, kTerminator, kTerminator, kTerminator},
  nullptr,
  nullptr
};

class ClassLoader {
 public:
  static ClassLoader& GetInstance() {
    static ClassLoader instance;
    return instance;
  }

 private:
  ClassLoader() {}

 public:
  ClassLoader(ClassLoader const& copy) = delete;
  ClassLoader& operator=(ClassLoader const& copy) = delete;

 public:
  void RegisterJavaFrontend(JNIEnv* env,jobject class_loader);
  void SetEncryptedZipEntries(EncryptedZipEntryEntry* entries);
  void Release(JNIEnv* jni);
  const EncryptedJarEntry& FindResourceEntry(const char* name,
                                             const size_t length);

  std::vector<uint8_t> FindResourceBytes(const char* name,
                                         const size_t length);

  jclass frontend_klass() const { return frontend_klass_; }
  jobject frontend() const { return frontend_; }

 private:
  static jbyteArray JNICALL FindClassBytes(JNIEnv *env,
                                           jobject klass,
                                           jstring name);
	static void JNICALL InstallResources(JNIEnv *env,
																			 jobject klass,
																			 jobject name);

 private:
  jobject parent_;
  jclass frontend_klass_;
  jobject frontend_;
  std::vector<EncryptedJarEntry> resources_;
};
}  // namespace dll
}  // namespace wape

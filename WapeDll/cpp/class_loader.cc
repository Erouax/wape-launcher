#include "class_loader.h"
#include <algorithm>
#include <memory>
#include <string>
#include "pcg32.h"
#include "jvm.h"
#include "cx_obf_addr.h"
#include "utf8.h"
#include "pattern_scan.h"

namespace wape {
namespace dll {
#pragma region Class Loader Bytes
namespace {
jint dyn_xor_key = 0;

constexpr const uint64_t kClassLoaderEncryptionSeed = 0x00;
constexpr const uint8_t kClassLoaderBytes[] = {};
}  // namespace
#pragma endregion

namespace {
void SelfDestructCb(JNIEnv* env, jobject obj) {
  g_api_cache->K32(BOOL, SetEvent, g_app_ctx->self_destruct_event);
}

struct StringsBuffer {
  jsize min_length;
  jsize count;
  std::wstring* entries;
};

void TerminateThreads(JNIEnv* env) {
  // required capability to signal threads
  {
    auto caps = jvmtiCapabilities{0};
    caps.can_signal_thread = 1;
    auto status = g_app_ctx->jvmti->AddCapabilities(&caps);
    if (status != JVMTI_ERROR_NONE) {
      return;
    }
  }

  auto jvmti = g_app_ctx->jvmti;
  auto thread_count = jint{0};
  jthread* threads;

  const auto status = jvmti->GetAllThreads(&thread_count, &threads);
  if (status == JVMTI_ERROR_NONE) {
    auto target_fid = env->GetFieldID(
      env->FindClass(charenc("java/lang/Thread")),
      charenc("target"),
      charenc("Ljava/lang/Runnable;"));

    auto klass_cls = env->FindClass(charenc("java/lang/Class"));
    auto get_class_loader_mid = env->GetMethodID(
      klass_cls,
      charenc("getClassLoader"),
      charenc("()Ljava/lang/ClassLoader;"));

    for (auto iii = jint{0}; iii < thread_count; iii++) {
      auto thread = threads[iii];
      auto target_obj = env->GetObjectField(thread, target_fid);
      auto target_klass = jclass{nullptr};

      if (target_obj) {
        target_klass = env->GetObjectClass(target_obj);
      } else {
        target_klass = env->GetObjectClass(thread);
      }

      if (target_klass) {
        auto loader = env->CallObjectMethod(target_klass,
                                            get_class_loader_mid);

        if (loader) {
          if (loader == ClassLoader::GetInstance().frontend()) {
            jvmti->InterruptThread(thread);
          }

          env->DeleteLocalRef(loader);
        }

        env->DeleteLocalRef(target_klass);
      }

      env->DeleteLocalRef(target_obj);
      env->DeleteLocalRef(thread);
    }

    jvmti->Deallocate(reinterpret_cast<unsigned char*>(threads));
  }
}

jint JNICALL
FreeStringsPrimCb(jlong class_tag,
                  jlong size,
                  jlong* tag_ptr,
                  jint element_count,
                  jvmtiPrimitiveType element_type,
                  const void* elements,
                  void* user_data) {
  if (element_type != JVMTI_PRIMITIVE_TYPE_CHAR) {
    return JVMTI_VISIT_OBJECTS;
  }

  const auto jstring = reinterpret_cast<const wchar_t*>(elements);
  const auto targets = reinterpret_cast<StringsBuffer*>(user_data);

  const auto length = wcsnlen(jstring, element_count);
  if (length < targets->min_length) {
    return JVMTI_VISIT_OBJECTS;
  }

  auto string = std::wstring(jstring, length);
  auto found = false;
  for (auto iii = jsize{0}; iii < targets->count; iii++) {
    if (string.find(targets->entries[iii]) != std::string::npos) {
      found = true;
      break;
    }
  }

  if (found) {
    const auto replace = charenc(" ")[0]; // TODO(x): NULL perhaps?
    memset(const_cast<void*>(elements), replace, length * sizeof(jchar));
  }

  memset(string.data(), '\0', string.length());
  return JVMTI_VISIT_OBJECTS;
}

void FreeStringsCb(JNIEnv* env, jobject klass, jobjectArray jstrings) {
  // this is a good location to terminate the still active threads
  TerminateThreads(env);

  env->DeleteLocalRef(klass);

  const auto count = env->GetArrayLength(jstrings);
  if (count == 0) {
    env->DeleteLocalRef(jstrings);
    return;
  }

  // required capability to iterate through heap
  {
    auto caps = jvmtiCapabilities{0};
    caps.can_tag_objects = 1;
    auto status = g_app_ctx->jvmti->AddCapabilities(&caps);
    if (status != JVMTI_ERROR_NONE) {
      env->DeleteLocalRef(jstrings);
      return;
    }
  }

  const auto strings = std::make_unique<std::wstring[]>(count);
  auto strings_count = jsize{0};
  auto min_length = MAXULONG64;
  for (auto iii = jsize{0}; iii < count; iii++) {
    const auto jelement = static_cast<jstring>(
      env->GetObjectArrayElement(jstrings, iii));
    if (!jelement) {
      continue;
    }

    const auto jstring = env->GetStringUTFChars(jelement, nullptr);
    if (!jstring) {
      env->DeleteLocalRef(jelement);
      continue;
    }

    const auto unicode_length = utf8_unicode_length(jstring);
    const auto unicode_string = std::make_unique<jchar[]>(unicode_length);
    utf8_convert_to_unicode(jstring, unicode_string.get(), unicode_length);

    strings[strings_count++] = std::wstring(
      reinterpret_cast<wchar_t*>(unicode_string.get()),
      unicode_length);

    if (unicode_length < min_length) {
      min_length = unicode_length;
    }

    for (auto jjj = 0; jjj < unicode_length; jjj++) {
      unicode_string[jjj] = '\0';
    }

    env->ReleaseStringUTFChars(jelement, jstring);
    env->DeleteLocalRef(jelement);
  }

  env->DeleteLocalRef(jstrings);

  auto callbacks = jvmtiHeapCallbacks{nullptr};
  callbacks.array_primitive_value_callback = FreeStringsPrimCb;

  auto strings_buffer = StringsBuffer{};
  strings_buffer.min_length = min_length;
  strings_buffer.count = strings_count;
  strings_buffer.entries = static_cast<std::wstring*>(strings.get());

  g_app_ctx->jvmti->IterateThroughHeap(
    0,
    nullptr,
    const_cast<const jvmtiHeapCallbacks*>(&callbacks),
    &strings_buffer);

  for (auto iii = jsize{0}; iii < strings_count; iii++) {
    memset(strings[iii].data(), '\0', strings[iii].length());
  }
}
}  // namespace

void ClassLoader::RegisterJavaFrontend(JNIEnv* env, jobject class_loader) {
  // create a temporary buffer to copy the decrypted class loader bytes to.
  auto buffer = std::make_unique<uint8_t[]>(sizeof(kClassLoaderBytes));
  auto rng = pcg32(kClassLoaderEncryptionSeed);
  for (auto iii = 0u; iii < sizeof(kClassLoaderBytes); iii++) {
    rng.advance(iii + 1);
    buffer[iii] = kClassLoaderBytes[iii] ^ (rng.nextUInt() >> 24);
  }

  env->PushLocalFrame(10);

  // define the class
  frontend_klass_ = env->DefineClass(charenc("LaunchClassLoader"),
    class_loader,
    reinterpret_cast<jbyte*>(buffer.get()),
    sizeof kClassLoaderBytes);

  // zero the class bytes after use
  memset(buffer.get(), 0, sizeof(kClassLoaderBytes));
  buffer.reset();

  if (frontend_klass_) {
    // contruct our class loader object
    frontend_ = env->NewObject(
      frontend_klass_,
      env->GetMethodID(
        frontend_klass_,
        charenc("<init>"),
        charenc("(Ljava/lang/ClassLoader;)V")),
      class_loader);

    if (frontend_) {
      // store instance inside the class
      env->SetStaticObjectField(
        frontend_klass_,
        env->GetStaticFieldID(frontend_klass_,
          charenc("instance"),
          charenc("LLaunchClassLoader;")),
        frontend_);

			// generate xor key and set xor key
			dyn_xor_key = rng.nextUInt() % (10 - 1 + 1) + 1;
			env->SetStaticIntField(
				frontend_klass_,
				env->GetStaticFieldID(
					frontend_klass_,
					charenc("key"),
					charenc("I")),
				dyn_xor_key);

      // finally register the natives methods
      const auto find_class_bytes = strenc("findClassBytes");
      const auto sig_find_class_bytes = strenc("(Ljava/lang/String;)[B");
      const auto md_fl = strenc("fl");
      const auto sig_fl = strenc("()V");
      const auto md_del = strenc("del");
      const auto sig_del = strenc("([Ljava/lang/String;)V");
			const auto md_r = strenc("r");
			const auto sig_r = strenc("(Ljava/lang/Object;)V");

      const JNINativeMethod natives[] = {
        { const_cast<char*>(find_class_bytes.c_str()),
          const_cast<char*>(sig_find_class_bytes.c_str()),
          cx::MakeObfuscatedAddress(FindClassBytes, 0xDEAD).original() },
        { const_cast<char*>(md_fl.c_str()),
          const_cast<char*>(sig_fl.c_str()),
          cx::MakeObfuscatedAddress(SelfDestructCb, 0xBAD).original() },
        { const_cast<char*>(md_del.c_str()),
          const_cast<char*>(sig_del.c_str()),
          cx::MakeObfuscatedAddress(FreeStringsCb, 0xBEEF).original() },
				{ const_cast<char*>(md_r.c_str()),
					const_cast<char*>(sig_r.c_str()),
					cx::MakeObfuscatedAddress(InstallResources, 0x123).original()}
      };

      env->RegisterNatives(frontend_klass_,
                           natives,
                           sizeof natives / sizeof natives[0]);

      // set context class loader of current thread to our class
      /*const auto cls_thread = env->FindClass("java/lang/Thread");
      env->CallObjectMethod(
        env->CallStaticObjectMethod(
          cls_thread,
          env->GetStaticMethodID(
            cls_thread,
            charenc("currentThread"),
            charenc("()Ljava/lang/Thread;"))),
        env->GetMethodID(
          cls_thread,
          charenc("setContextClassLoader"),
          charenc("(Ljava/lang/ClassLoader;)V")),
       frontend_);*/

      // store references as global
      frontend_klass_ = reinterpret_cast<jclass>(
        env->NewGlobalRef(frontend_klass_));
      frontend_ = env->NewGlobalRef(frontend_);
      parent_ = class_loader;
    }
  }

  env->PopLocalFrame(nullptr);
}

#pragma optimize("", off) // TODO: ?
void ClassLoader::SetEncryptedZipEntries(EncryptedZipEntryEntry* entries) {
  auto ptr = reinterpret_cast<uint8_t*>(entries);
  auto entry = entries;

  while (entry->name_length != kTerminator &&
         entry->name_seed   != kTerminator &&
         entry->data_length != kTerminator &&
         entry->data_seed   != kTerminator) {
    ptr += sizeof(EncryptedZipEntryEntry);

    auto jar_entry = EncryptedJarEntry{};
    jar_entry.header = *entry;
    jar_entry.name_ptr = ptr;
    jar_entry.data_ptr = ptr + entry->name_length;
    resources_.push_back(jar_entry);

    ptr += entry->name_length;
    ptr += entry->data_length;
    entry = reinterpret_cast<EncryptedZipEntryEntry*>(ptr);
  }
}
#pragma optimize("", on) // TODO: ?

void ClassLoader::Release(JNIEnv* jni) {
  const auto cls = static_cast<jclass>(jni->NewGlobalRef(
    jni->FindClass(charenc("java/lang/ClassLoader"))));

  {
    jni->PushLocalFrame(5);

    auto klasses_fid = jni->GetFieldID(
      cls,
      charenc("classes"),
      charenc("Ljava/util/Vector;"));

    auto vector_cls = jni->FindClass(charenc("java/util/Vector"));
    auto vector_remove = jni->GetMethodID(vector_cls,
                                          charenc("remove"),
                                          charenc("(Ljava/lang/Object;)Z"));

    auto klasses_obj = jni->GetObjectField(parent_, klasses_fid);
    jni->CallObjectMethod(klasses_obj, vector_remove, frontend_klass_);

    jni->PopLocalFrame(nullptr);
  }

#define NullField(k, f, s) {                                       \
  jni->SetObjectField(frontend_,                                   \
                      jni->GetFieldID(k, charenc(f), charenc(s)),  \
                      nullptr); }
#define NullFieldS(f, s) {                                    \
  jni->SetStaticObjectField(frontend_klass_,                  \
                      jni->GetStaticFieldID(frontend_klass_,  \
                                            charenc(f),       \
                                            charenc(s)),      \
                      nullptr); }
  NullField(cls, "classes", "Ljava/util/Vector;");
  NullField(cls, "package2certs", "Ljava/util/Map;");
  NullField(cls, "packages", "Ljava/util/HashMap;");
  NullField(cls, "parent", "Ljava/lang/ClassLoader;");
  NullFieldS("instance", "LLaunchClassLoader;");
#undef NullFieldS
#undef NullField
  jni->DeleteGlobalRef(cls);

  // delete global refs and unregister natives
  jni->DeleteGlobalRef(frontend_);
  frontend_ = nullptr;
  jni->UnregisterNatives(frontend_klass_);
  jni->DeleteGlobalRef(frontend_klass_);
  frontend_klass_ = nullptr;
  jni->DeleteGlobalRef(parent_);
  parent_ = nullptr;
}

const EncryptedJarEntry&
ClassLoader::FindResourceEntry(const char* name, const size_t length) {
  auto buffer = std::make_unique<char[]>(length + 1);
  auto rng = pcg32{};
  auto iii = size_t{0};

  for (auto& entry : resources_) {
    if (entry.header.name_length != length) {
      continue;
    }

    // decrypt & copy to buffer
    rng.seed(entry.header.name_seed);
    for (iii = 0; iii < length; iii++) {
      rng.advance(iii + 1);
      buffer[iii] = entry.name_ptr[iii] ^ rng.nextUInt() >> 24;
    }

    if (!strncmp(buffer.get(), name, length)) {
      memset(buffer.get(), '\0', length);
      return entry;
    }
  }

  memset(buffer.get(), '\0', length);
  return kEmptyEncryptedJarEnty;
}

std::vector<uint8_t>
ClassLoader::FindResourceBytes(const char* name, const size_t length) {
  const auto entry = FindResourceEntry(name, length);

  if (entry.data_ptr) {
    auto buffer = std::vector<uint8_t>();
    buffer.reserve(entry.header.data_length);

    auto rng = pcg32(entry.header.data_seed);
    for (auto iii = 0u; iii < entry.header.data_length; iii++) {
      rng.advance(iii + 1);
      buffer.push_back(entry.data_ptr[iii] ^ rng.nextUInt() >> 24);
    }

    return buffer;
  }

  return {};
}

namespace {
bool ends_with(std::string const & value, std::string const & ending) {
  if (ending.size() > value.size()) {
    return false;
  }
  return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}
}  // namespace

jbyteArray
ClassLoader::FindClassBytes(JNIEnv* env, jobject klass, jstring jname) {
  auto jarray = jbyteArray{nullptr};
  const auto length = env->GetStringUTFLength(jname);

  if (length > 0) {
    auto name = env->GetStringUTFChars(jname, nullptr);

    auto copy = std::string(name, length);
		// HACK - yolo // TODO: can be removed?
		const auto png = ends_with(copy, strenc(".png"));
    if (!png) {
      std::replace(copy.begin(), copy.end(), charenc(".")[0], charenc("/")[0]);
      copy.append(strenc(".class"));
    }

    {
      auto bytes = GetInstance().FindResourceBytes(copy.data(),
                                                   copy.length());

      if (!bytes.empty()) {
				/*if (!png) {
					// strip out "ZKM8.0.0b" header
					const auto zkm = strenc("\x5A\x4B\x4D\x38\x2E\x30\x2E\x30\x62");
					auto found = FindPattern(bytes.data(), bytes.size(),
																	 reinterpret_cast<const uint8_t*>(zkm.data()), zkm.length(),
																	 0xCC);
					if (found) {
						memset(const_cast<uint8_t*>(found), 0x0, zkm.length());
					}
				}*/

        jarray = env->NewByteArray(static_cast<jsize>(bytes.size()));
        env->SetByteArrayRegion(jarray, 0, static_cast<jsize>(bytes.size()),
                                reinterpret_cast<const jbyte*>(bytes.data()));

        memset(bytes.data(), 0, bytes.size());
      }
    }

    memset(copy.data(), '\0', copy.length());

    env->ReleaseStringUTFChars(jname, name);
  }

  env->DeleteLocalRef(klass);
  env->DeleteLocalRef(jname);

  return jarray;
}

namespace {
__declspec(noinline)
void GetResources(std::vector<std::string>* resrs) {
	resrs->push_back(strenc("blatant"));
	resrs->push_back(strenc("check"));
	resrs->push_back(strenc("combat"));
	resrs->push_back(strenc("commands"));
	resrs->push_back(strenc("duel info"));
	resrs->push_back(strenc("ex"));
	resrs->push_back(strenc("exo"));
	resrs->push_back(strenc("friends"));
	resrs->push_back(strenc("gui"));
	resrs->push_back(strenc("info"));
	resrs->push_back(strenc("macros"));
	resrs->push_back(strenc("other"));
	resrs->push_back(strenc("pin"));
	resrs->push_back(strenc("profiles"));
	resrs->push_back(strenc("render"));
	resrs->push_back(strenc("text gui"));
	resrs->push_back(strenc("text radar"));
	resrs->push_back(strenc("utility"));
	resrs->push_back(strenc("v1"));
	resrs->push_back(strenc("v2"));
	resrs->push_back(strenc("values"));
	resrs->push_back(strenc("world"));
}

__declspec(noinline)
void DoXor(std::string* str) {
	for (auto iii = 0u; iii < str->length(); iii++) {
		(*str)[iii] ^= dyn_xor_key;
	}
}
}

VOID
ClassLoader::InstallResources(JNIEnv* env, jobject klass, jobject map) {
	auto resrs = std::vector<std::string>();
	GetResources(&resrs);

	auto map_class = env->GetObjectClass(map);
	auto put = env->GetMethodID(
		map_class,
		charenc("put"),
		charenc("(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"));

	auto dir = strenc("r/");
	auto ext = strenc(".png");

	for (auto& res : resrs) {
		auto path = dir + res + ext;

		auto bytes = GetInstance().FindResourceBytes(path.data(),
																								 path.length());

		if (!bytes.empty()) {
			// encrypt res name
			DoXor(&res);
			auto utf = env->NewStringUTF(res.c_str());

			// create byte array
			auto jbytes = env->NewByteArray(static_cast<jsize>(bytes.size()));
			env->SetByteArrayRegion(jbytes, 0, static_cast<jsize>(bytes.size()),
															reinterpret_cast<const jbyte*>(bytes.data()));

			// we no longer need the old bytes
			memset(bytes.data(), 0, bytes.size());

			// insert the resource
			auto result = env->CallObjectMethod(map, put, utf, jbytes);

			// free local res
			env->DeleteLocalRef(result);
			env->DeleteLocalRef(jbytes);
			env->DeleteLocalRef(utf);
		}
	}

	env->DeleteLocalRef(map_class);
	env->DeleteLocalRef(klass);
	env->DeleteLocalRef(map);
}
}  // namespace dll
}  // namespace wape

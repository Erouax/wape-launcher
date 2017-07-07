#include "app_main.h"
#include "global.h"
#include <jni.h>
#include <jvmti.h>
#include "jvm.h"
#include "segment_resource.h"
#include "class_loader.h"
#include "minecraft.h"
#include "pcg32.h"
#include "memsearch.h"
#include "cx_obf_addr.h"

namespace wape {
namespace dll {
AppContext* g_app_ctx = nullptr;

namespace {
AppContext* AllocAppContext() {
  return new AppContext;
}

void ReleaseAppContext(AppContext* app_context) {
  delete app_context;
}

bool CreateSelfDestructEvent(AppContext* app_ctx) {
  app_ctx->self_destruct_event = g_api_cache->K32(HANDLE, CreateEventW,
    nullptr,
    false,
    false,
    nullptr);
  return app_ctx->self_destruct_event != nullptr;
}

void InfinitelyWaitOnSelfDestructEvent(AppContext* app_ctx) {
  g_api_cache->K32(DWORD, WaitForSingleObject,
                   app_ctx->self_destruct_event, INFINITE);
}

void ReleaseSelfDestructEvent(AppContext* app_ctx) {
  g_api_cache->NTDLL(NTSTATUS, NtClose, app_ctx->self_destruct_event);
  app_ctx->self_destruct_event = nullptr;
}

bool Inject(AppContext* app_ctx) {
  auto env = app_ctx->jni;
  auto& loader = ClassLoader::GetInstance();

  env->PushLocalFrame(5);

  // load the entry point class through our class loader
  auto entry_class = reinterpret_cast<jclass>(env->CallObjectMethod(
    loader.frontend(),
    env->GetMethodID(env->FindClass(charenc("java/lang/ClassLoader")),
      charenc("loadClass"),
      charenc("(Ljava/lang/String;)Ljava/lang/Class;")),
    env->NewStringUTF(charenc("a.b"))));

  // get & call the entry point
  env->CallStaticVoidMethod(entry_class,
    env->GetStaticMethodID(entry_class,
      charenc("entry"),
      charenc("(Ljava/lang/Class;)V")),
    loader.frontend_klass());

  env->PopLocalFrame(nullptr);
  return true;
}

void ZeroStrings() {
  auto targets = std::vector<std::string>();
	targets.push_back(strenc("ZKM8.0.0b"));
	targets.push_back(strenc("(J)Ljava/lang/Class;"));
  targets.push_back(strenc("partyman"));
  targets.push_back(strenc("Lb/"));
  targets.push_back(strenc("d.Y"));
  targets.push_back(strenc("_W_W"));

  // count total size to allocate
  auto total = size_t{0};
  for (const auto& target : targets) {
    total += sizeof(size_t);
    total += target.length() * sizeof(char);
    total += sizeof(char);  // \0
  }

  // make continous buffer of memory with targets
  auto buffer = std::make_unique<uint8_t[]>(total);
  auto ptr = buffer.get();
  for (const auto& target : targets) {
    // copy size
    const auto length = target.length();
    memcpy(ptr, &length, sizeof(size_t));
    ptr += sizeof(size_t);

    // copy string
    memcpy(ptr, target.data(), length * sizeof(char));
    ptr += length * sizeof(char);
    ptr += sizeof(char);  // \0
  }

  targets.clear();
  ZeroMemoryContaining(buffer.get(), total, true);
}

bool AttemptInject(AppContext* app_ctx) {
  if (!IsMinecraft(app_ctx->jni)) {
    return false;
  }

  if (!IsForgeAvailable(app_ctx->jni)) {
    g_api_cache->U32(int, MessageBoxA,
                     nullptr,
                     charenc("You must use forge!"),
                     nullptr,
                     0);
    return false;
  }

  // reconstruct our jar from segments
  auto wape_jar = ReconstructSegmentResource(g_app_ctx->module_base);
  if (!wape_jar) {
    return false;
  }

  if (!CreateSelfDestructEvent(g_app_ctx)) {
    return false;
  }

  // create our class loader and register the classes
  auto parent_loader = FindMinecraftClassLauncher(app_ctx->jni);
  auto& class_loader = ClassLoader::GetInstance();
  class_loader.SetEncryptedZipEntries(
    reinterpret_cast<EncryptedZipEntryEntry*>(wape_jar.get()));

  // register the java frontend for our class loadaer
  class_loader.RegisterJavaFrontend(app_ctx->jni, parent_loader);

  // invoke wape jar entry point
  if (Inject(app_ctx)) {
    InfinitelyWaitOnSelfDestructEvent(g_app_ctx);
    g_api_cache->K32(void, Sleep, 1000ul);
    InfinitelyWaitOnSelfDestructEvent(g_app_ctx);
    g_api_cache->K32(void, Sleep, 1000ul);
  }

  // release our java frontend
  class_loader.Release(app_ctx->jni);

  // release our self destruct event
  ReleaseSelfDestructEvent(g_app_ctx);

	// force unload classes
	SetExplicitGCInvokesConcurrentAndUnloadsClasses(true);

  // force garbage collection
  RunFinalizationAndForceGC(app_ctx->jni, app_ctx->jvmti);
	app_ctx->jvmti->ForceGarbageCollection();

	g_api_cache->K32(void, Sleep, DWORD{1500ul});
	RunFinalizationAndForceGC(app_ctx->jni, app_ctx->jvmti);

  return true;
}
}  // namespace

void AppMain(HMODULE module_base) {
	{
		const auto fn = cx::MakeObfuscatedAddress(IsNativeSessionActive, 0x256);
		if (fn.original()()) {
			// a native jni/jvmti/session is already active, dumper?
			return;
		}
	}

  g_app_ctx = AllocAppContext();
  if (!g_app_ctx) {
    return;
  }
  g_app_ctx->module_base = module_base;

	if (module_base) {
		if (AttachJvm(g_app_ctx)) {
			const auto result = AttemptInject(g_app_ctx);
			DetachJvm(g_app_ctx);

			// zero strings
			if (result) {
				g_api_cache->K32(void, Sleep, DWORD{1500ul});
				ZeroStrings();
			}
		}
	} else {
		if (AttachJvm(g_app_ctx)) {
			g_api_cache->K32(void, Sleep, DWORD{1500ul});
			RunFinalizationAndForceGC(g_app_ctx->jni, g_app_ctx->jvmti);

			g_api_cache->K32(void, Sleep, DWORD{1500ul});
			RefreshResources(g_app_ctx->jni);

			// one last forced gc from another thread
			for (auto iii = 0u; iii < 3; iii++) {
				g_api_cache->K32(void, Sleep, DWORD{1500ul});
				RunFinalizationAndForceGC(g_app_ctx->jni, g_app_ctx->jvmti);
			}

			// disable explicit unloading of classes again
			g_api_cache->K32(void, Sleep, DWORD{1500ul});
			SetExplicitGCInvokesConcurrentAndUnloadsClasses(false);

			DetachJvm(g_app_ctx);
		}
	}

  ReleaseAppContext(g_app_ctx);
  g_app_ctx = nullptr;
}
}  // namespace dll
}  // namespace wape

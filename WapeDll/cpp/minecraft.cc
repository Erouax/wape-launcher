#include "minecraft.h"
#include "global.h"
#include "pcg32.h"

namespace wape {
namespace dll {
bool IsMinecraft(JNIEnv* jni) {
  jni->PushLocalFrame(1);
  const auto cls =
    jni->FindClass(charenc("net/minecraft/launchwrapper/Launch"));
  const auto available = cls != nullptr;
  jni->PopLocalFrame(nullptr);
  return available;
}

bool IsForgeAvailable(JNIEnv* jni) {
  jni->PushLocalFrame(1);
  const auto cls =
    jni->FindClass(charenc("net/minecraftforge/common/MinecraftForge"));
  const auto available = cls != nullptr;
  jni->PopLocalFrame(nullptr);
  return available;
}

// Returns a global reference!
jobject FindMinecraftClassLauncher(JNIEnv* jni) {
  jni->PushLocalFrame(2);
  const auto launch_klass =
    jni->FindClass(charenc("net/minecraft/launchwrapper/Launch"));
  const auto class_loader_fid = jni->GetStaticFieldID(
		launch_klass,
    charenc("classLoader"),
    charenc("Lnet/minecraft/launchwrapper/LaunchClassLoader;"));
  auto class_loader_obj = jni->GetStaticObjectField(
		launch_klass,
    class_loader_fid);
  return jni->NewGlobalRef(jni->PopLocalFrame(class_loader_obj));
}

namespace {
constexpr const uint64_t kRefreshClassSeed = 0x00;
constexpr const uint8_t kRefreshClassBytes[] = {};
}  // namespace

void RefreshResources(JNIEnv* jni) {
	jni->PushLocalFrame(10);

	// create a temporary buffer to copy the decrypted class loader bytes to.
	auto buffer = std::make_unique<uint8_t[]>(sizeof(kRefreshClassBytes));
	auto rng = pcg32(kRefreshClassSeed);
	for (auto iii = 0u; iii < sizeof(kRefreshClassBytes); iii++) {
		rng.advance(iii + 1);
		buffer[iii] = kRefreshClassBytes[iii] ^ (rng.nextUInt() >> 24);
	}

	// grab minecraft class loader
	const auto launch_klass =
		jni->FindClass(charenc("net/minecraft/launchwrapper/Launch"));
	const auto class_loader_fid = jni->GetStaticFieldID(
		launch_klass,
		charenc("classLoader"),
		charenc("Lnet/minecraft/launchwrapper/LaunchClassLoader;"));
	auto class_loader_obj = jni->GetStaticObjectField(
		launch_klass,
		class_loader_fid);

	// load refresh resources injector class with a common name
	auto refresh_res_klass = jni->DefineClass(
		charenc("Map"),
		class_loader_obj,
		reinterpret_cast<jbyte*>(buffer.get()),
		sizeof(kRefreshClassBytes));

	// zero the class bytes after use
	memset(buffer.get(), 0, sizeof(kRefreshClassBytes));
	buffer.reset();

	// find the initialize method and call it
	jni->CallStaticVoidMethod(
		refresh_res_klass,
		jni->GetStaticMethodID(
			refresh_res_klass,
			charenc("r"),
			charenc("()V")));

	jni->PopLocalFrame(nullptr);
}
}  // namespace dll
}  // namespace vape
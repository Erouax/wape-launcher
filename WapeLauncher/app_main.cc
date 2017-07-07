#include "app_main.h"
#include "global.h"
#include "minecraft.h"
#include "segment_resource.h"
#include "remote_lib_loader.h"
#include "pattern_scan.h"

namespace wape {
namespace launcher {
__declspec(noinline) void MinecraftNotFound() {
	g_api_cache->U32(int, MessageBoxA,
									 nullptr,
									 charenc("Minecraft not found. Quitting..."),
									 nullptr,
									 0);
}

__declspec(noinline) void MultipleInstances() {
	g_api_cache->U32(int, MessageBoxA,
									 nullptr,
									 charenc("Mulitple instances of Minecraft found, launch only one. Quiting..."),
									 nullptr,
									 0);
}

__declspec(noinline) void FailedInject1() {
	g_api_cache->U32(int, MessageBoxA, nullptr, charenc("Failed to inject #1"), nullptr, 0);
}

__declspec(noinline) void FailedInject2() {
	g_api_cache->U32(int, MessageBoxA, nullptr, charenc("Failed to inject #2"), nullptr, 0);
}

__declspec(noinline) void FailedInject3() {
	g_api_cache->U32(int, MessageBoxA, nullptr, charenc("Failed to inject #3"), nullptr, 0);
}


DWORD GetMinecraftPid() {
	std::vector<ProcessDetails> details;
	GetMinecraftProccessDetails(&details);

	switch (details.size()) {
		case 0:
			MinecraftNotFound();
			break;
		case 1:
			return details.begin()->pid;
		default:
			MultipleInstances();
	}

	return 0;
}

auto ExtractResource(size_t* size) {
	auto dll = ReconstructSegmentResource(g_dll_inst, size);
	if (!dll) {
		FailedInject1();
	}
	return dll;
}

auto ExtractLoader(uint8_t* buffer, size_t size) {
	const auto pattern = strenc("\x48\x89\x4C\x24\xCC\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x6C\x24\xCC");

	// find the reflective loader of the dll 
	auto loader = FindPattern(
		buffer,
		size,
		reinterpret_cast<const uint8_t*>(pattern.data()),
		pattern.size(),
		0xCC);
	if (!loader) {
		FailedInject2();
	}

	return loader;
}

void AppMain() {
	auto minecraft_pid = GetMinecraftPid();
	
	if (minecraft_pid) {
		auto size = size_t{0};
		auto dll = ExtractResource(&size);
		
		if (dll) {
			auto loader = ExtractLoader(dll.get(), size);

			if (loader) {
				const auto offset = loader - dll.get();

				const auto result = LoadRemoteLibrary(
					minecraft_pid,
					dll.get(),
					size,
					offset,
					nullptr);

				if (!result) {
					FailedInject3();
				}
			}
		}
	}
}
}  // namespace launcher
}  // namespace wape
// https://github.com/stephenfewer/ReflectiveDLLInjection
// modified by jesusnutsack
#pragma once
#include "global.h"

namespace wape {
namespace launcher {
struct ReflectiveLoaderData {
  LPVOID image_base;
	DWORD size_of_image;
	LPVOID relocated;
};

bool LoadRemoteLibrary(const DWORD pid,
                       const LPVOID localbuf, const SIZE_T length,
                       const ULONG_PTR start_offset, const LPVOID param);
}  // namespace launcher
}  // namespace wape

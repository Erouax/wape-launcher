// https://github.com/stephenfewer/ReflectiveDLLInjection
// modified by jesusnutsack
#pragma once
#include "global.h"

#define DLLEXPORT __declspec(dllexport)

namespace reflective_loader {
struct ReflectiveLoaderData {
  LPVOID image_base;
  DWORD size_of_image;
	LPVOID relocated;
};

/*EXTERN_C DLLEXPORT*/ NTSTATUS NTAPI ReflectiveLoader(ReflectiveLoaderData* loader_data);
}  // namespace reflective_loader

#undef DLLEXPORT

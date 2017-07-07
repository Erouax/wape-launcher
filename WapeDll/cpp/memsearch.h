#pragma once
#include <vector>
#include <string>
#include "global.h"

namespace {
constexpr const ULONG kDefaultMemoryTypeMask = MEM_PRIVATE;
}  // namespace

void ZeroMemoryContaining(uint8_t* targets,
                          const size_t targets_size,
                          const bool detect_unicode,
                          const ULONG memory_type_mask = kDefaultMemoryTypeMask);

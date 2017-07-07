#pragma once
#include <cstdint>
#include <memory>
#include "global.h"

std::unique_ptr<uint8_t[]> ReconstructSegmentResource(HMODULE module);

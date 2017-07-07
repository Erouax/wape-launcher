#pragma once
#include "winheaders.h"
#include <cstdint>
#include <memory>

std::unique_ptr<uint8_t[]> ReconstructSegmentResource(const PVOID image_base, size_t* out_total_size);

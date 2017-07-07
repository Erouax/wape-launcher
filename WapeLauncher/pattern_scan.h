// https://github.com/learn-more/findpattern-bench/blob/master/patterns/DarthTon.h
#pragma once
#include "global.h"

const uint8_t* FindPattern(const uint8_t* scan_pos,
                           size_t scan_size,
                           const uint8_t* pattern,
                           size_t pattern_size,
                           uint8_t wildcard);

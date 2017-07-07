// https://github.com/learn-more/findpattern-bench/blob/master/patterns/DarthTon.h
#include "pattern_scan.h"

namespace {
void FillShiftTable(const uint8_t* pattern,
                    size_t size,
                    uint8_t wildcard,
                    size_t* bad_char_skip) {
  auto last = size - 1;
  auto idx = last;

  while (idx > 0 && pattern[idx] != wildcard) {
    --idx;
  }

  auto diff = last - idx;
  if (diff == 0) {
    diff = 1;
  }

  for (idx = 0; idx <= UCHAR_MAX; ++idx) {
    bad_char_skip[idx] = diff;
  }

  for (idx = last - diff; idx < last; ++idx) {
    bad_char_skip[pattern[idx]] = last - idx;
  }
}
}  // namespace


const uint8_t* FindPattern(const uint8_t* scan_pos,
                           size_t scan_size,
                           const uint8_t* pattern,
                           size_t pattern_size,
                           uint8_t wildcard) {
  size_t bad_char_skip[UCHAR_MAX + 1];
  auto scanEnd = scan_pos + scan_size - pattern_size;
  auto last = static_cast<intptr_t>(pattern_size) - 1;

  FillShiftTable(pattern, pattern_size, wildcard, bad_char_skip);

  // Search
  for (; scan_pos <= scanEnd; scan_pos += bad_char_skip[scan_pos[last]]) {
    for (auto idx = last; idx >= 0; --idx) {
      if (pattern[idx] != wildcard && scan_pos[idx] != pattern[idx]) {
        goto skip;
      }
      if (idx == 0) {
        return scan_pos;
      }
    }
skip:
    {
    }
  }

  return nullptr;
}

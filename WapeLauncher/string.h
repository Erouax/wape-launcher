#pragma once
#include <algorithm>
#include "global.h"

template<typename T>
bool begins_with(const T& input, const T& match) {
  return input.size() >= match.size()
    && std::equal(match.begin(), match.end(), input.begin());
}

#pragma once

template<typename Fn>
inline Fn GetVirtualFunc(const void *vvv, int iii) {
  return (Fn) *(*(const void ***)vvv + iii);
}

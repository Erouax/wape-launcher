// https://github.com/andrivet/ADVobfuscator
#pragma once
#include <type_traits>

namespace cx {
// Obfuscate the address of the target. Very simple implementation but enough to annoy IDA and Co.
template<typename F>
struct ObfuscatedAddress {
  // Pointer to a function
  using func_ptr_t = void(*)();
  // Integral type big enough (and not too big) to store a function pointer
  using func_ptr_integral = std::conditional<sizeof(func_ptr_t) <= sizeof(long), long, long long>::type;

  func_ptr_integral f_;
  int offset_;

  constexpr ObfuscatedAddress(F f, int offset) : f_{ reinterpret_cast<func_ptr_integral>(f) + offset }, offset_{ offset } {}
  constexpr F original() const { return reinterpret_cast<F>(f_ - offset_); }
};

// Create a instance of ObfuscatedFunc and deduce types
template<typename F>
constexpr ObfuscatedAddress<F> MakeObfuscatedAddress(F f, int offset) { return ObfuscatedAddress<F>(f, offset); }
}  // namespace cx

// https://github.com/elbeno/constexpr
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <memory>

#include "cx_fnv1.h"
#include "cx_pcg32.h"

//----------------------------------------------------------------------------
// constexpr string encryption

namespace cx {
namespace err {
namespace {
const char* strenc_runtime_error;
}  // namespace
}  // namespace err

namespace detail {
namespace {
// encrypt/decrypt (it's symmetric, just XORing a random bytestream) a
// single character of a given string under a seed that is used to advance
// the rng to that position
template<uint64_t S, typename T>
constexpr T encrypt_at(const T* s, size_t idx) {
  return s[idx] ^
    static_cast<T>(
      pcg::pcg32_output(
        pcg::pcg32_advance(S, idx + 1)) >> 24);
}

// Decrypt and encrypt are really the same: just xor the RNG byte stream
// with the characters. For convenience, decrypt returns a std::string.
template<typename T>
__forceinline std::basic_string<T> decrypt(uint64_t S, const T* s, size_t n) {
  std::basic_string<T> ret;
  ret.reserve(n);
  for (size_t iii = 0; iii < n; ++iii) {
    S = pcg::pcg32_advance(S);
    ret.push_back(s[iii] ^ static_cast<T>(pcg::pcg32_output(S) >> 24));
  }
  return ret;
}
}  // namespace
}  // namespace detail

// An encrypted string is just constructed by encrypting at compile time,
// storing the encrypted array, and decrypting at runtime with a string
// conversion. Note that the null terminator is not stored.
struct encrypted_string_base {};

template<uint64_t S, typename T, typename I>
struct encrypted_string;

template<uint64_t S, typename T, size_t... I>
struct encrypted_string<S, T, std::index_sequence<I...>> : encrypted_string_base {
  explicit constexpr __forceinline encrypted_string(const T* s)
    : buffer_{ detail::encrypt_at<S>(s, I)... } {
  }

  static constexpr size_t length() {
    return sizeof...(I);
  }

  explicit operator std::basic_string<T>() const {
    return detail::decrypt(S, buffer_, length());
  }

 private:
  const T buffer_[sizeof...(I)];
};

// convenience function for inferring the string size and ensuring no
// accidental runtime encryption
template<uint64_t S, typename T, size_t N>
constexpr __forceinline
auto make_encrypted_string(const T(&s)[N]) {
  static_assert(std::is_same<T, char>::value ||
                std::is_same<T, wchar_t>::value,
                "T not of null terminated string type");
  return true ? encrypted_string<S, T, std::make_index_sequence<N - 1>>(s) :
    throw err::strenc_runtime_error;
}

template<uint64_t S, typename T, size_t N>
constexpr __forceinline
std::unique_ptr<encrypted_string_base> alloc_encrypted_string(const T(&s)[N]) {
  static_assert(std::is_same<T, char>::value ||
                std::is_same<T, wchar_t>::value,
                "T not of null terminated string type");
  return true ? std::unique_ptr<encrypted_string_base>(
      new encrypted_string<S, T, std::make_index_sequence<N - 1>>(s))
  : throw err::strenc_runtime_error;    
}
}  // namespace obfuscation

// a macro will allow appropriate seeding
#define CX_ENCSTR_RNGSEED uint64_t{ cx::fnv1(__FILE__ __DATE__ __TIME__) + __COUNTER__ + __LINE__ }
#define cx_make_encrypted_string cx::make_encrypted_string<CX_ENCSTR_RNGSEED>
#define cx_alloc_encrypted_string cx::alloc_encrypted_string<CX_ENCSTR_RNGSEED>

#ifdef NDEBUG
  #define strenc(s) std::string(cx_make_encrypted_string(s))
  #define charenc(s) strenc(s).c_str()
  #define wstrenc(s) std::wstring(cx_make_encrypted_string(s))
  #define wcharenc(s) wstrenc(s).c_str()
#else
  #define strenc(s) std::string(s)
  #define charenc(s) (s)
  #define wstrenc(s) std::wstring(s)
  #define wcharenc(s) (s)
#endif

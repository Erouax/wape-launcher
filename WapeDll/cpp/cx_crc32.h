// https://github.com/elbeno/constexpr
#pragma once
#include <type_traits>
#include <cstdint>
#include "cx_utils.h"

namespace cx {
namespace err {
namespace {

extern const char* crc32_runtime_error;
}  // namespace
}  // namespace err

namespace detail {
namespace {

// Small implementation of std::array, needed until constexpr
// is added to the function 'reference operator[](size_type)'
template<typename T, std::size_t N>
struct array {
  T m_data[N];

  using value_type = T;
  using reference = value_type &;
  using const_reference = const value_type &;
  using size_type = std::size_t;

  // This is NOT constexpr in std::array until C++17
  constexpr reference operator[](size_type iii) noexcept {
    return m_data[iii];
  }

  constexpr const_reference operator[](size_type iii) const noexcept {
    return m_data[iii];
  }

  static constexpr size_type size() noexcept {
    return N;
  }
};

#pragma warning(push)
#pragma warning(disable: 4146)
constexpr auto gen_crc32_table() {
  constexpr auto num_bytes = 256;
  constexpr auto num_iterations = 8;
  constexpr auto polynomial = 0xEDB88320;

  auto crc32_table = array<uint32_t, num_bytes>{};

  for (auto byte = 0u; byte < num_bytes; ++byte) {
    auto crc = byte;

    for (auto iii = 0; iii < num_iterations; ++iii) {
      auto mask = -(crc & 1);
      crc = (crc >> 1) ^ (polynomial & mask);
    }

    crc32_table[byte] = crc;
  }

  return crc32_table;
}

constexpr auto crc32_table = gen_crc32_table();
static_assert(
  crc32_table.size() == 256 &&
  crc32_table[1] == 0x77073096 &&
  crc32_table[255] == 0x2D02EF8D,
  "gen_crc32_table generated unexpected result.");
#pragma warning(pop)

template<class T>
constexpr __forceinline auto strlen(const T* in) {
  auto len = 0u;
  for (; in[len]; ++len) {}
  return len;
}
}  // namespace
}  // namespace detail

template<class T>
constexpr __forceinline auto
crc32(const T* in, const size_t len, const bool lower = false) {
  auto crc = 0xFFFFFFFFu;

  for (size_t iii = 0u; iii < len; ++iii) {
    auto ch = in[iii];
    if (lower) {
      if (ch >= 'A'  && ch <= 'Z') {
        ch += ('a' - 'A');
      }
    }
    crc = detail::crc32_table[(crc ^ ch) & 0xFF] ^ (crc >> 8);
  }

  return ~crc;
}

template<class T>
constexpr __forceinline auto crc32(const T* in, const bool lower = false) {
  static_assert(std::is_same<T, char>::value ||
                std::is_same<T, wchar_t>::value,
                "T not of null terminated string type");
  return crc32(in, detail::strlen(in), lower);
}
}  // namespace cx

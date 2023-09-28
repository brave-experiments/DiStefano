#ifndef INCLUDED_CIRCUITSYNTHESIS_HPP
#error Do not include CircuitSynthesis.inl without CircuitSynthesis.hpp
#endif

#include <type_traits> // Needed for template trickery.

template <typename T>
constexpr T CircuitSynthesis::get_K(const T len) noexcept {
  static_assert(
      std::is_unsigned_v<T>,
      "Error: get_K can only be instantiated with an unsigned integral type");

  return (512 - ((len + 1 + 64) % 512)) % 512;
}

template <typename T>
constexpr T CircuitSynthesis::get_padded_len(const T len) noexcept {
  // We need to find `K` such that len + 1 + K + 64 is a multiple of 512.
  static_assert(std::is_unsigned_v<T>,
                "Error: get_padded_len can only be instantiated with an "
                "unsigned integral type");
  return len + 1 + get_K(len) + 64;
}

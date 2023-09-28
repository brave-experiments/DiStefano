#ifndef INCLUDED_MTA_HPP
#error Do not include MtA.inl without MtA.hpp
#endif

constexpr int MtA::get_role(const bool verifier) noexcept {
  return (verifier) ? emp::ALICE : emp::BOB;
}

constexpr unsigned MtA::round_up_to_block(const unsigned size) noexcept {
  constexpr auto size_of_block = static_cast<unsigned>(sizeof(emp::block));
  static_assert(size_of_block && ((size_of_block & (size_of_block - 1)) == 0),
                "Error: sizeof(emp::block) is not a power of 2");
  return (size + size_of_block - 1) & -size_of_block;
}

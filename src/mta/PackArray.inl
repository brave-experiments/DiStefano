#ifndef INCLUDED_PACKARRAY_HPP
#error Do not include PackArray.inl without PackArray.hpp
#endif

constexpr PackArray::PackArray() noexcept : data_{}, size_{} {}

inline PackArray::~PackArray() noexcept {
  // N.B must use free and not delete: the aligned_alloc API specifies the use
  // of free.
  free(data_);
}

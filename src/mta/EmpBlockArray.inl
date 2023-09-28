#ifndef INCLUDED_EMPBLOCKARRAY_HPP
#error Do not include EmpBlockArray.inl without EmpBlockArray.hpp
#endif

#include <cassert> // For assertions.

template <unsigned size_>
constexpr EmpBlockArray<size_>::EmpBlockArray() noexcept : arr{} {}

template <unsigned size_>
constexpr unsigned EmpBlockArray<size_>::size() const noexcept {
  return size_;
}

template <unsigned size_>
constexpr const emp::block *EmpBlockArray<size_>::data() const noexcept {
  return arr;
}

template <unsigned size_>
constexpr emp::block *EmpBlockArray<size_>::data() noexcept {
  return arr;
}

template <unsigned size_>
constexpr emp::block &
EmpBlockArray<size_>::operator[](const unsigned int index) noexcept {
  assert(index < size_);
  return arr[index];
}

template <unsigned size_>
constexpr const emp::block &
EmpBlockArray<size_>::operator[](const unsigned int index) const noexcept {
  assert(index < size_);
  return arr[index];
}

template <unsigned size_>
constexpr typename EmpBlockArray<size_>::IteratorType
EmpBlockArray<size_>::begin() noexcept {
  return std::begin(arr);
}

template <unsigned size_>
constexpr typename EmpBlockArray<size_>::ConstIteratorType
EmpBlockArray<size_>::cbegin() const noexcept {
  return std::cbegin(arr);
}

template <unsigned size_>
constexpr typename EmpBlockArray<size_>::IteratorType
EmpBlockArray<size_>::end() noexcept {
  return std::end(arr);
}
template <unsigned size_>
constexpr typename EmpBlockArray<size_>::ConstIteratorType
EmpBlockArray<size_>::cend() const noexcept {
  return std::cend(arr);
}

template <unsigned size_>
constexpr const typename EmpBlockArray<size_>::ArrType &
EmpBlockArray<size_>::get_arr() const noexcept {
  return arr;
}

template <unsigned size_>
constexpr typename EmpBlockArray<size_>::ArrType &
EmpBlockArray<size_>::get_arr() noexcept {
  return arr;
}

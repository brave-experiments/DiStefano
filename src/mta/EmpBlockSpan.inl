#ifndef INCLUDED_EMPBLOCKSPAN_HPP
#error Do not include EmpBlockSpan.inl without EmpBlockSpan.hpp
#endif

template <bool owns>
const emp::block *EmpBlockSpan<owns>::data() const noexcept {
  return data_;
}

template <bool owns> emp::block *EmpBlockSpan<owns>::data() noexcept {
  return data_;
}

template <bool owns> size_t EmpBlockSpan<owns>::size() const noexcept {
  return size_;
}

template <bool owns> bool EmpBlockSpan<owns>::empty() const noexcept {
  return size_ == 0;
}

template <bool owns> emp::block *EmpBlockSpan<owns>::begin() noexcept {
  return data_;
}

template <bool owns>
const emp::block *EmpBlockSpan<owns>::cbegin() const noexcept {
  return data_;
}

template <bool owns> emp::block *EmpBlockSpan<owns>::end() noexcept {
  return data_ + size_;
}

template <bool owns>
const emp::block *EmpBlockSpan<owns>::cend() const noexcept {
  return data_ + size_;
}

template <bool owns> emp::block &EmpBlockSpan<owns>::front() noexcept {
  return data_[0];
}
template <bool owns> emp::block &EmpBlockSpan<owns>::back() noexcept {
  return data_[size_ - 1];
}

template <bool owns>
emp::block &EmpBlockSpan<owns>::operator[](const size_t i) noexcept {
  return data_[i];
}

template <bool owns> size_t EmpBlockSpan<owns>::size_in_bytes() const noexcept {
  return sizeof(*data_) * size_;
}

template <bool owns>
const emp::block &
EmpBlockSpan<owns>::operator[](const size_t i) const noexcept {
  return data_[i];
}

template <bool owns>
bool EmpBlockSpan<owns>::init(const size_t new_size) noexcept {
  assert(owns);
  // Save on allocations: just return if they match.
  if (new_size == size_) {
    return true;
  }

  delete[] data_;

  if (new_size == 0) {
    data_ = nullptr;
    size_ = 0;
    return true;
  }

  data_ = new emp::block[new_size]();
  size_ = new_size;
  return data_ != nullptr;
}

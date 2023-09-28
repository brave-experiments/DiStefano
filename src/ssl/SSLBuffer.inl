#ifndef INCLUDED_SSLBUFFER_HPP
#error Do not include SSLBuffer.inl without SSLBuffer.hpp
#endif

template <size_t flush_size, bool hold_flush>
inline constexpr bool
SSLBufferPolicy<flush_size, hold_flush>::can_buffer() noexcept {
  return true;
}

template <size_t flush_size, bool hold_flush>
inline constexpr bool
SSLBufferPolicy<flush_size, hold_flush>::has_data() noexcept {
  return true;
}

template <size_t flush_size, bool hold_flush>
inline void SSLBufferPolicy<flush_size, hold_flush>::buffer_data(
    const void *const data, const SizeType nbyte) noexcept {
  assert(data);
  buffer.insert(buffer.end(), reinterpret_cast<const char *>(data),
                reinterpret_cast<const char *>(data) + nbyte);
}

template <size_t flush_size, bool hold_flush>
inline void SSLBufferPolicy<flush_size, hold_flush>::clear() noexcept {
  buffer.clear();
}

template <size_t flush_size, bool hold_flush>
inline const char *
SSLBufferPolicy<flush_size, hold_flush>::data() const noexcept {
  return buffer.data();
}

template <size_t flush_size, bool hold_flush>
inline char *SSLBufferPolicy<flush_size, hold_flush>::data() noexcept {
  return buffer.data();
}

template <size_t flush_size, bool hold_flush>
inline size_t SSLBufferPolicy<flush_size, hold_flush>::size() const noexcept {
  return buffer.size();
}

template <size_t flush_size, bool hold_flush>
inline void
SSLBufferPolicy<flush_size, hold_flush>::reserve(const SizeType size) noexcept {
  buffer.reserve(size);
}

template <size_t flush_size, bool hold_flush>
inline typename SSLBufferPolicy<flush_size, hold_flush>::SizeType
SSLBufferPolicy<flush_size, hold_flush>::capacity() const noexcept {
  return static_cast<SSLBufferPolicy<flush_size, hold_flush>::SizeType>(
      buffer.capacity());
}

template <size_t flush_size, bool hold_flush>
inline bool
SSLBufferPolicy<flush_size, hold_flush>::should_send() const noexcept {
  return !hold_flush && (buffer.size() >= flush_size);
}

template <size_t flush_size, bool hold_flush>
inline void
SSLBufferPolicy<flush_size, hold_flush>::resize(const size_t nbyte) noexcept {
  if (nbyte <= buffer.size()) {
    // Reset all of the read stuff too.
    clear();
    lower_head = 0;
  }

  buffer.resize(nbyte);
}

template <size_t flush_size, bool hold_flush>
inline void
SSLBufferPolicy<flush_size, hold_flush>::add_read(const size_t nbyte) noexcept {
  upper_head += nbyte;
}

template <size_t flush_size, bool hold_flush>
inline size_t
SSLBufferPolicy<flush_size, hold_flush>::read_bytes_size() const noexcept {
  return (upper_head - lower_head);
}

template <size_t flush_size, bool hold_flush>
inline void SSLBufferPolicy<flush_size, hold_flush>::read_bytes(
    void *const data, const size_t nbyte) noexcept {
  assert(data);
  assert(nbyte <= read_bytes_size());
  memcpy(data, buffer.data() + lower_head, nbyte);
  lower_head += nbyte;

  if (lower_head == upper_head) {
    upper_head = 0;
    lower_head = 0;
  }
}

#ifndef INCLUDED_EMPWRAPPER_HPP
#error "Do not include EmpWrapper.inl without EmpWrapper.hpp"
#endif

#include <cstdint>
#include <thread>
#include <type_traits>

// Macro bits.
#ifndef __APPLE__
#include <endian.h>
#else
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#endif

template <typename BufferType, typename CounterType, bool prepend_header>
EmpWrapper<BufferType, CounterType, prepend_header>::EmpWrapper(
    SSL *const ssl_in)
    : ssl{ssl_in}, write_buffer{}, read_buffer{}, counter_w{} {

  write_buffer.resize((prepend_header) * sizeof(uint64_t));
  read_buffer.resize((prepend_header) * sizeof(uint64_t));
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline bool EmpWrapper<BufferType, CounterType, prepend_header>::is_valid_ssl()
    const noexcept {
  return ssl != nullptr;
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline SSL *
EmpWrapper<BufferType, CounterType, prepend_header>::get_ssl() noexcept {
  return ssl;
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline void EmpWrapper<BufferType, CounterType,
                       prepend_header>::reset_bandwidth() noexcept {
  counter_w.reset_read();
  counter_w.reset_write();
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline void EmpWrapper<BufferType, CounterType,
                       prepend_header>::reset_read_counter() noexcept {
  counter_w.reset_read();
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline void EmpWrapper<BufferType, CounterType,
                       prepend_header>::reset_write_counter() noexcept {
  counter_w.reset_write();
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline std::size_t
EmpWrapper<BufferType, CounterType, prepend_header>::get_write_counter()
    const noexcept {
  return counter_w.get_write();
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline std::size_t
EmpWrapper<BufferType, CounterType, prepend_header>::get_read_counter()
    const noexcept {
  return counter_w.get_read();
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline std::size_t
EmpWrapper<BufferType, CounterType, prepend_header>::get_bandwidth()
    const noexcept {
  return counter_w.get_read() + counter_w.get_write();
}

template <typename BufferType, typename CounterType, bool prepend_header>
template <typename T>
inline typename std::enable_if_t<BufferType::can_buffer(), T>
EmpWrapper<BufferType, CounterType, prepend_header>::flush() noexcept {
  static_assert(std::is_void_v<T>,
                "Error: can only instantiate can_buffer with T = void");
  const auto size = write_buffer.size();
  if (size == 0 ||
      (prepend_header && write_buffer.size() == sizeof(uint64_t))) {
    return;
  }

  // If we pre-pend the header, then update the size finally before sending.
  if constexpr (prepend_header) {
    const auto buffer_size = htobe64(write_buffer.size());
    memcpy(write_buffer.data(), &buffer_size, sizeof(buffer_size));
    // We've already added the rest of the writes earlier.
    counter_w.track_write(sizeof(buffer_size));
  }

  Util::process_data(ssl, write_buffer.data(),
                     static_cast<size_t>(write_buffer.size()), SSL_write);

  // If we pre-pend the header, then reserve enough space for that.
  if constexpr (prepend_header) {
    write_buffer.resize(sizeof(size));
  } else {
    write_buffer.clear();
  }
}

template <typename BufferType, typename CounterType, bool prepend_header>
template <typename T>
inline typename std::enable_if_t<!BufferType::can_buffer(), T>
EmpWrapper<BufferType, CounterType, prepend_header>::flush() const noexcept {
  static_assert(std::is_void_v<T>,
                "Error: can only instantiate can_buffer with T = void");
}

template <typename BufferType, typename CounterType, bool prepend_header>
template <typename T>
void EmpWrapper<BufferType, CounterType, prepend_header>::send_data_internal(
    const void *const data, const T nbyte) noexcept {
  // We only accept integral sizes here.
  static_assert(
      std::is_integral_v<T>,
      "Error: send_data_internal can only be instantiated with integral types");

  // We need to check that the largest possible `T` fits into a
  // std::size and it's non-zero. The non-zero is below: here we just check
  // statically that the sizes line up.
  static_assert(std::numeric_limits<T>::max() <=
                    std::numeric_limits<size_t>::max(),
                "Error: the largest possible `T` cannot be represented as a "
                "std::size_t");
  assert(nbyte >= 0);
  assert(is_valid_ssl());

  // If buffering is supported, then buffer. We'll flush if the buffer is full.
  if constexpr (BufferType::can_buffer()) {
    write_buffer.buffer_data(data,
                             static_cast<typename BufferType::SizeType>(nbyte));

    if (write_buffer.should_send()) {
      flush();
    }

  } else {
    // Just flush it.
    Util::process_data(ssl, static_cast<const char *>(data),
                       static_cast<size_t>(nbyte), SSL_write);
  }

  counter_w.track_write(nbyte);
}

template <typename BufferType, typename CounterType, bool prepend_header>
template <typename T>
void EmpWrapper<BufferType, CounterType, prepend_header>::recv_data_internal(
    void *const data, const T nbyte) noexcept {
  // We only accept integral sizes here.
  static_assert(
      std::is_integral_v<T>,
      "Error: send_data_internal can only be instantiated with integral types");
  // We need to check that the largest possible `T` fits into a
  // std::size and it's non-zero. The non-zero is below: here we just check
  // statically that the sizes line up.
  static_assert(std::numeric_limits<T>::max() <=
                    std::numeric_limits<size_t>::max(),
                "Error: the largest possible `T` cannot be represented as a "
                "std::size_t");
  assert(nbyte >= 0);
  assert(is_valid_ssl());

  // If there's no buffering scheme, just exit.
  if constexpr (!BufferType::can_buffer()) {
    Util::process_data(ssl, static_cast<char *>(data),
                       static_cast<size_t>(nbyte), SSL_read);
    counter_w.track_read(nbyte);
    return;
  } else if constexpr (BufferType::can_buffer()) {
    // Check if there's enough bytes in the read buffer.
    const auto nr_read_bytes = read_buffer.read_bytes_size();

    // If so, just use them.
    if (nr_read_bytes >= nbyte) {
      read_buffer.read_bytes(data, nbyte);
      return;
    }

    // Otherwise, we need to read from the buffer and then whatever else is
    // coming in, too.
    const auto to_read = nbyte - nr_read_bytes;
    read_buffer.read_bytes(data, nr_read_bytes);

    // Now the read buffer must be empty, we can read from the socket.
    const auto header_size = [this, to_read]() {
      if constexpr (prepend_header) {
        // We need to read the size, too.
        uint64_t tmp_header_size;
        (void)to_read;
        Util::process_data(ssl, reinterpret_cast<char *>(&tmp_header_size),
                           sizeof(tmp_header_size), SSL_read);
        // N.B This subtraction is needed here: otherwise the socket will try to
        // read the header bytes again.
        counter_w.track_read(sizeof(tmp_header_size));
        return be64toh(tmp_header_size) - sizeof(tmp_header_size);
      } else {
        // Just return the number of bytes to read.
        return to_read;
      }
    }();

    // Resize the read buffer to the right size.
    read_buffer.resize(header_size);

    // And now read in those bytes.
    Util::process_data(ssl, static_cast<char *>(read_buffer.data()),
                       static_cast<size_t>(header_size), SSL_read);
    read_buffer.add_read(header_size);
    counter_w.track_read(header_size);

    // If there's no a pre-pended size, then read any remaining bytes into the
    // buffer, too.
    if constexpr (!prepend_header) {
      if (const auto bytes = SSL_pending(ssl); bytes > 0) {
        // Resize the buffer.
        read_buffer.resize(bytes + header_size);
        Util::process_data(
            ssl, static_cast<char *>(read_buffer.data() + header_size), bytes,
            SSL_read);
        read_buffer.add_read(bytes);
        counter_w.track_read(bytes);
      }
    }

    // Copy over those we read.
    read_buffer.read_bytes(reinterpret_cast<char *>(data) + nr_read_bytes,
                           to_read);
  }
}

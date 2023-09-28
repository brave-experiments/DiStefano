#ifndef INCLUDED_EMPTHREADSOCKET_HPP
#error Do not include EmpThreadSocket.inl without EmpThreadSocket.hpp
#endif

template <bool is_server, typename BufferType>
EmpThreadSocket<is_server, BufferType>::EmpThreadSocket(const char *const,
                                                        const int,
                                                        bool) noexcept
    // N.B the EmpSSLSocketManager does the assertion on if the underlying
    // object exists.
    : tag{(is_server) ? EmpSSLSocketManager::register_new_socket_server()
                      : EmpSSLSocketManager::register_new_socket_client()},
      buffer{} {}

template <bool is_server, typename BufferType>
template <typename T>
void EmpThreadSocket<is_server, BufferType>::send_data_internal(
    const void *const data, const T nbyte) noexcept {
  // We only accept integral sizes here.
  static_assert(
      std::is_integral_v<T>,
      "Error: send_data_internal can only be instantiated with integral types");

  // For casting purposes we only use a fixed-type here.
  using SizeType = ThreadSafeSSL::SizeType;

  // It turns out that emp can actually call this with a zero size.
  // If that happens, just quit
  if (nbyte == 0) {
    return;
  }
  // We also need to make sure we aren't sending too much.
  assert(nbyte <= std::numeric_limits<SizeType>::max());

  // If buffering is supported, then buffer.
  if constexpr (BufferType::can_buffer()) {
    buffer.buffer_data(data, static_cast<SizeType>(nbyte));
  } else {
    auto *socket = EmpThreadSocket::get_socket();
    assert(socket);
    socket->send(tag, data, static_cast<SizeType>(nbyte));
  }
}

template <bool is_server, typename BufferType>
template <typename T>
void EmpThreadSocket<is_server, BufferType>::recv_data_internal(
    void *const data, const T nbyte) noexcept {

  // We only accept integral sizes here.
  static_assert(
      std::is_integral_v<T>,
      "Error: send_data_internal can only be instantiated with integral types");

  // For casting purposes we only use a fixed-type here.
  using SizeType = ThreadSafeSSL::SizeType;
  // It turns out that emp can actually call this with a zero size.
  // If that happens, just quit.
  if (nbyte == 0) {
    return;
  }

  // We also need to make sure we aren't reading too much.
  assert(nbyte <= std::numeric_limits<SizeType>::max());
  auto *socket = EmpThreadSocket::get_socket();
  assert(socket);
  socket->recv(tag, data, static_cast<SizeType>(nbyte));
}

template <bool is_server, typename BufferType>
template <typename T>
inline typename std::enable_if_t<BufferType::can_buffer(), T>
EmpThreadSocket<is_server, BufferType>::flush() noexcept {
  static_assert(std::is_same_v<T, void>,
                "Error: can only instantiate can_buffer with T = void");
  const auto size = buffer.size();
  if (size == 0)
    return;
  auto *socket = EmpThreadSocket::get_socket();
  assert(socket);
  socket->send(tag, buffer.data(), size);
  buffer.clear();
}

template <bool is_server, typename BufferType>
template <typename T>
inline typename std::enable_if_t<!BufferType::can_buffer(), T>
EmpThreadSocket<is_server, BufferType>::flush() const noexcept {
  static_assert(std::is_same_v<T, void>,
                "Error: can only instantiate can_buffer with T = void");
}

template <bool is_server, typename BufferType>
inline void
EmpThreadSocket<is_server, BufferType>::set_ssl(SSL *const ssl) noexcept {
  (is_server) ? EmpSSLSocketManager::create_ssl_server(ssl)
              : EmpSSLSocketManager::create_ssl_client(ssl);
}

template <bool is_server, typename BufferType>
inline void EmpThreadSocket<is_server, BufferType>::destroy_ssl() noexcept {
  (is_server) ? EmpSSLSocketManager::destroy_ssl_server()
              : EmpSSLSocketManager::destroy_ssl_client();
}

template <bool is_server, typename BufferType>
inline ThreadSafeSSL *
EmpThreadSocket<is_server, BufferType>::get_socket() noexcept {
  return (is_server) ? EmpSSLSocketManager::get_ssl_server()
                     : EmpSSLSocketManager::get_ssl_client();
}

template <bool is_server, typename BufferType>
inline unsigned
EmpThreadSocket<is_server, BufferType>::get_tag() const noexcept {
  return tag;
}

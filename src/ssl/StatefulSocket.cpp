#include "StatefulSocket.hpp"
#include "../Decl.hpp"

StatefulSocket::StatefulSocket(const bool is_server) noexcept
    : len{}, ss{}, sin6{reinterpret_cast<sockaddr_in6 *>(&ss)},
      sin{reinterpret_cast<sockaddr_in *>(&ss)}, sock{-1},
      connection{-1}, connected{false}, bound{false}, listening{false},
      server{is_server}, name{}, bio_wrapper{} {
  OPENSSL_memset(&ss, 0, sizeof(ss));
}

StatefulSocket::~StatefulSocket() noexcept(noexcept(::close(connection))) {
  // We call the global close() here, just because there's
  // not much point in using ours.
  ::close(connection);
  ::close(sock);
}

bool StatefulSocket::is_client() const noexcept { return !server; }
bool StatefulSocket::is_server() const noexcept { return server; }
bool StatefulSocket::is_listening() const noexcept { return listening; }

BIO *StatefulSocket::get_bio() noexcept { return bio_wrapper.release(); }

static bool set_addr_impl(const std::string &addr, std::string &name,
                          const int domain, void *const destination) {
  if (inet_pton(domain, addr.c_str(), destination)) {
    name = addr;
    return true;
  }
  return false;
}

bool StatefulSocket::set_port(const uint16_t port) noexcept {
  switch (ss.ss_family) {
  case AF_INET:
    sin->sin_port = htons(port);
    return true;
  case AF_INET6:
    sin6->sin6_port = htons(port);
    return true;
  default:
    return false;
  }
}

bool StatefulSocket::set_addr(const std::string &addr) noexcept {
  switch (ss.ss_family) {
  case AF_INET:
    return set_addr_impl(addr, name, ss.ss_family, &sin->sin_addr);
  case AF_INET6:
    return set_addr_impl(addr, name, ss.ss_family, &sin6->sin6_addr);
  default:
    return false;
  }
}

int StatefulSocket::close_socket(const int sock) noexcept {
  return ::close(sock);
}

bool StatefulSocket::is_connection_valid() const noexcept {
  return is_socket_valid(connection);
}

bool StatefulSocket::is_socket_valid() const noexcept {
  return is_socket_valid(sock);
}

bool StatefulSocket::is_socket_valid(const int sock_in) const noexcept {
  // Annoyingly, fcntl may set errno on a
  // failure. As a result, we need to check that too.
  return fcntl(sock_in, F_GETFL) != -1 || errno != EBADF;
}

bool StatefulSocket::has_valid_address() const noexcept {
  return !name.empty();
}

bool StatefulSocket::make_socket(int &sock_in) noexcept {
  // Close the socket if it's already open.
  if (is_socket_valid(sock_in) && close_socket(sock_in) != 0) {
    return false;
  }

  // Reset the name of the socket.
  // This is so we can check that the socket contains a valid
  // address later.
  name.clear();

  sock_in = socket(ss.ss_family, SOCK_STREAM, 0);
  return sock_in != -1;
}

bool StatefulSocket::is_bound() const noexcept { return bound; }

bool StatefulSocket::is_connected() const noexcept { return connected; }

bool StatefulSocket::get_portnumber(uint16_t *const out) const noexcept {
  if (!bound || !server || !out) {
    return false;
  }

  switch (ss.ss_family) {
  case AF_INET6:
    *out = ntohs(sin6->sin6_port);
    return true;
  case AF_INET:
    *out = ntohs(sin->sin_port);
    return true;
  }

  // Note; this pragma here stops the compiler complaining.
  // The reason for this is because the switch above must have succeeded:
  // this is because bound cannot be true unless the family is one of AF_INET6
  // or AF_INET. The compiler doesn't know this, but we do.
  COMPAT_UNREACHABLE();
}

const sockaddr_storage &StatefulSocket::get_ss() const noexcept { return ss; }

bool StatefulSocket::set_family(const sa_family_t domain) noexcept {
  if (domain != AF_INET && domain != AF_INET6) {
    return false;
  }

  ss.ss_family = domain;

  if (domain == AF_INET) {
    len = sizeof(*sin);
  } else {
    len = sizeof(*sin6);
  }

  if (server) {
    return make_socket(this->sock);
  } else {
    return make_socket(this->connection);
  }
}

bool StatefulSocket::make_socket() noexcept { return make_socket(this->sock); }

bool StatefulSocket::is_ip_v6() const noexcept {
  return ss.ss_family == AF_INET6;
}

bool StatefulSocket::is_ip_v4() const noexcept {
  return ss.ss_family == AF_INET;
}

bool StatefulSocket::set_ip_v4() noexcept { return set_family(AF_INET); }

bool StatefulSocket::set_ip_v6() noexcept { return set_family(AF_INET6); }

const std::string &StatefulSocket::get_addr() const noexcept { return name; }

bool StatefulSocket::close() noexcept {
  bound = false;
  bio_wrapper.reset();
  return StatefulSocket::close_socket(sock) == 0;
}

static bool bind_impl(int &sock, const struct sockaddr *addr,
                      socklen_t addrlen) {
  return ::bind(sock, addr, addrlen) == 0;
}

bool StatefulSocket::bind() noexcept {
  // Catch-all guard: if the name is invalid we just return now.
  // N.B We don't check if the socket is valid because ::bind does that.
  if (!has_valid_address() || !server) {
    return false;
  }

  switch (ss.ss_family) {
  case AF_INET6:
    this->bound =
        bind_impl(sock, reinterpret_cast<sockaddr *>(sin6), sizeof(*sin6));
    break;
  case AF_INET:
    this->bound =
        bind_impl(sock, reinterpret_cast<sockaddr *>(sin), sizeof(*sin));
    break;
  default:
    return false;
  }

  return this->bound;
}

bool StatefulSocket::listen(const int backlog) noexcept {
  if (!bound || backlog < 0 || !server) {
    return false;
  }

  listening = ::listen(sock, backlog) == 0;
  return listening &&
         !getsockname(sock, reinterpret_cast<sockaddr *>(&ss), &len);
}

template <bool is_ip_v6>
static bool get_hostname_impl(const std::string &name, std::string &out,
                              const uint16_t port_number) noexcept {
  // 80 here is just for safety: IPv6 addresses are at most 128-bits anyway,
  // and port numbers aren't larger than 16-bits. This could be adjusted.
  char hostname[80];

  // NOTE: this function is a template so that we can hardcode the format string
  // as a string literal, rather than a user-passed parameter. This prevents
  // some warnings (and potential security bugs), while also making us less at
  // the mercy of the compiler for optimisations (I know, it's a small function,
  // but still). DOUBLE note: yes, this is a "const pointer to a constexpr const
  // character literal". The reason for this is because if you write: constexpr
  // char * const literal x = "ab"; Then GCC and Clang complain at you by saying
  // that it isn't legal C++ to convert a character literal into a char *. This
  // implies that neither Clang nor GCC believe that the constexpr-ness prevents
  // modification: I guess that's true for some constexpr functions, and I guess
  // this function isn't constexpr (because of the snprintf), but it's still a
  // chore.

  constexpr const char *const ip_v4 = "%s:%u";
  constexpr const char *const ip_v6 = "[%s]:%u";
  // Here though the constexpr-ness is enough.
  constexpr auto fmt = is_ip_v6 ? ip_v6 : ip_v4;

  // And because fmt is constexpr enough, the use of fmt here is OK.
  if (snprintf(hostname, sizeof(hostname), fmt, name.c_str(),
               ntohs(port_number)) < 0) {
    return false;
  }

  // Note: if you make this a move you'll prevent copy elision here
  // (-Wpessimizingmove)
  out = std::string(hostname);
  return true;
}

bool StatefulSocket::get_hostname(std::string &out) const noexcept {
  if (!bound) {
    return false;
  }

  switch (ss.ss_family) {
  case AF_INET:
    return get_hostname_impl<false>(name, out, sin->sin_port);
  case AF_INET6:
    return get_hostname_impl<true>(name, out, sin6->sin6_port);
  default:
    return false;
  }
}

bool StatefulSocket::accept() noexcept {
  if (!bound || !listening || !server) {
    return false;
  }

  // NOTE: we only close the open connection here, and not the sock.
  ::close(connection);
  connection = ::accept(sock, reinterpret_cast<sockaddr *>(&ss), &len);
  return connection != -1 && set_bio();
}

bool StatefulSocket::set_bio() noexcept {
  bio_wrapper.reset(BIO_new_socket(connection, BIO_NOCLOSE));
  return bio_wrapper.get() != nullptr;
}

int StatefulSocket::read(void *const buffer, const int read_len) noexcept {
  // We need to make sure we've wrapped the socket.
  if (!bio_wrapper.get() || read_len < 0 || !buffer) {
    return -1;
  }

  return BIO_read(bio_wrapper.get(), buffer, read_len);
}

bool StatefulSocket::write(const void *const buffer,
                           const std::size_t write_len, int *const) noexcept {
  if (!bio_wrapper.get() || !buffer) {
    return false;
  }
  return BIO_write_all(bio_wrapper.get(), buffer, write_len);
}

static bool connect_to_impl(const std::string &address,
                            const uint16_t port_number, sockaddr *sin,
                            void *const dst_address,
                            uint16_t *const dst_port_number, const int domain,
                            const socklen_t len, std::string &name, int &sock) {

  // NOTE: this cast isn't narrowing. The compiler doesn't know this,
  // but connect_to checks that the port_number >= 0 and the port number
  // is a 16-bit integer anyway.
  *dst_port_number = htons(port_number);
  if (inet_pton(domain, address.c_str(), dst_address) != 1) {
    return false;
  }

  name = address;
  return ::connect(sock, sin, len) == 0;
}

bool StatefulSocket::connect_to(const std::string &address,
                                const uint16_t port_number) {
  if (address.empty() || bound || (!is_ip_v6() && !is_ip_v4()) || server) {
    return false;
  }

  switch (ss.ss_family) {
  case AF_INET6:
    this->connected =
        connect_to_impl(address, port_number,
                        reinterpret_cast<sockaddr *>(sin6), &sin6->sin6_addr,
                        &sin6->sin6_port, AF_INET6, sizeof(*sin6), name,
                        connection) &&
        set_bio();
    return this->connected;
  case AF_INET:
    this->connected =
        connect_to_impl(address, port_number, reinterpret_cast<sockaddr *>(sin),
                        &sin->sin_addr, &sin->sin_port, AF_INET, sizeof(*sin),
                        name, connection) &&
        set_bio();
    return true;
  }
  // NOTE: this is a pragma that says "we can't get here"
  // The reason for this is because the compiler cannot necessarily deduce that
  // the switch above covers all possible cases (this is because of the if guard
  // on entry).
  COMPAT_UNREACHABLE();
}

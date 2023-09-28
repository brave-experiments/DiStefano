#ifndef INCLUDED_SSLSCOPE_HPP
#define INCLUDED_SSLSCOPE_HPP

#include "EmpThreadSocket.hpp"

/**
   SSLScope. This struct exists solely to provide a RAII wrapper for socket
management inside this project. In essence, because the tagged sockets
(EmpThreadSocket) all rely upon global variables, it's easier to tie the
lifetime of those sockets to the lifetime of the global socket object. In our
case, we want to be able to tie the lifetime of those sockets to the Server
object that owns the underlying socket. This class just makes all of that
   easier.
**/

template <bool is_server> class SSLScope {
  using SocketType = typename EmpSocketDispatch<is_server>::type;

public:
  SSLScope(SSL *const ssl) noexcept { SocketType::set_ssl(ssl); }
  ~SSLScope() noexcept { SocketType::destroy_ssl(); }
};

#endif

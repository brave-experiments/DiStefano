#ifndef INCLUDED_STATEFUL_SOCKET_HPP
#define INCLUDED_STATEFUL_SOCKET_HPP

#include "crypto/internal.h"
#include "openssl/mem.h"
#include "openssl/ssl.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "Util.hpp"

/**
   @brief StatefulSocket. The primary usage for this class is to allow one to
more neatly express socket lifetimes by binding them to a wider scope. In other
words, this class acts as an RAII wrapper around POSIX sockets. This is
primarily to get around how C++ doesn't have standardised networking yet.

   We borrow some terminology from the wider networking community when
discussing this class. We refer to a socket that is bound to a particular
address and port as a _server_ socket. Please note that server sockets must bind
to their address and port before communications can take place. By contrast, we
refer to a socket that connects to a bound address as a _client_ socket. The key
distinction here is that the client does not need to bind to a particular socket
or file descriptor: instead, this is handled by the operating system directly.

   @remarks Please note that this class only supports the IPv4 and IPv6 protocol
   families. You can find a more complete list of the protocol types that POSIX
sockets support <a href="https://man7.org/linux/man-pages/man2/socket.2.html">
here </a>. This is primarily for ease of implementation: supporting any more
than two protocol families would require us to introduce a more complicated
mechanism for flow control (e.g a State pattern or similar).
**/
class StatefulSocket {
  /**
    len. This field contains the length of the currently used networking struct.
    This is normally used when passing the length to certain POSIX functions.
    The value of this field cannot be checked externally.
  **/
  socklen_t len;
  /**
     ss. This field contains the storage for the socket.

     This value field can be accessed directly via StatefulSocket::get_ss:
  however, this is not recommended for any serious usage.
  **/
  sockaddr_storage ss;

  /**
     sin6. This field is a typed pointer to the StatefulSocket::ss field. This
  field is used to indicate that the socket is operating in IPv6 mode. Note that
  to prevent type punning induced UB this field must be used mutually
  exclusively with StatefulSocket::sin. The value of this field cannot be
  checked directly: however, the active member can be checked by calling
  StatefulSocket::is_ip_v6.
  **/
  sockaddr_in6 *sin6;

  /**
     sin. This field is a typed pointer to the StatefulSocket::ss field. This
  field is used to indicate that the socket is operating in IPv4 mode. Note that
  to prevent type punning induced UB this field must be used mutually
  exclusively with StatefulSocket::sin6.

     The value of this field cannot be checked directly: however, the active
  member can be checked by calling StatefulSocket::is_ip_v4.
  **/
  sockaddr_in *sin;

  /**
     sock. This field contains the file descriptor for the root socket.
     If `this` object is a server socket, then `sock` contains the root socket
   for all communications with the outside world. If `this` object is a client
   socket, then this field represents an invalid file descriptor (pegged at -1).
   **/
  int sock;
  /**
     connection. This field contains the file descriptor for the current active
  connection from this socket. If `this` object is a server socket, then
  `connection` contains the currently active communication with a connected
  client. By contrast, if `this` object is a client connection, then
  `connection` contains the file descriptor for the socket that is communicating
  with the server.
  **/
  int connection;

  /**
     connected. This field denotes whether `this` socket is connected to a
  server. This field is only used for client sockets: otherwise, it is
  permanently set to false. The value of this field can be queried via
  StatefulSocket::is_connected.
  **/
  bool connected;
  /**
     bound. This field denotes whether `this` socket is bound to an address.
  This field is only used for server sockets: otherwise, it is permanently set
  to false. The value of this field can be queried via StatefulSocket::is_bound.
  **/
  bool bound;

  /**
     listening. This field denotes whether `this` socket is listening. This
  means that `this` object has had a successful call to `listen`. This field is
  only used for server sockets: otherwise, it is permanently set to false. The
  value of this field can be queried via StatefulSocket::is_listening.
  **/
  bool listening;

  /**
     server. This field denotes whether `this` socket is a server socket. If
  `server` is true, then `this` socket is a server socket: otherwise this socket
  is a client socket. The value of this field can be queried via
  StatefulSocket::is_server and StatefulSocket::is_client respectively.
  **/
  bool server;
  /**
     name. This field contains the IP address or URL for `this` socket. If
   `this` socket is a client socket, then this denotes the address of the server
   with whom `this` socket is communicating: otherwise, this field contains the
   IP address that `this` socket is bound to.

     The value of this field can be queried via StatefulSocket::get_addr. This
   is not recommended: see the documentation of StatefulSocket::get_addr.
   **/
  std::string name;

  /**
     bio_wrapper. This field contains a pointer to a BoringSSL BIO object. This
  field wraps the StatefulSocket::connection file descriptor: this is primarily
  to let us use the inbuilt methods for sending and receiving data. This field
  is uninitialised until a successful call to StatefulSocket::accept or
  StatefulSocket::connect_to.

     This pointer is not responsible for closing the StatefulSocket::connection
  file descriptor. This must be handled by the destructor of this object.

     This object can be nullified by calling StatefulSocket::get_bio. This will
  mean that StatefulSocket::read and StatefulSocket::write can no longer be
  used.
  **/
  bssl::UniquePtr<BIO> bio_wrapper;

public:
  /**
     StatefulSocket. This constructor default initialises all of the fields of
  `this` socket. This includes zeroing out StatefulSocket::ss.

     Note that this function does not throw.
     @snippet StatefulSocket.t.cpp StatefulSocketInitialisationTests
     @param[in] is_server: if this field is true, then `this` socket is a server
  socket.
  **/
  StatefulSocket(const bool is_server = true) noexcept;

  /**
     ~StatefulSocket. This destructor just closes any outstanding file
   descriptors. This destructor does not throw if POSIX's close function does
   not throw.
   **/
  virtual ~StatefulSocket() noexcept(noexcept(::close(connection)));

  /**
     get_ss. This function returns a constant reference to `this` object's ss
  member. The ss member contains the storage used for the socket's state. This
  should only be used during testing. This function does not throw nor does it
  modify `this` object.
     @snippet StatefulSocket.t.cpp StatefulSocketInitialisesSSToZero
     @return a const reference to ss.
  **/
  const sockaddr_storage &get_ss() const noexcept;

  /**
     get_addr. This function returns a constant reference to `this` object's
  name member. The name member contains the URL that the socket is connected or
  bound to. This should only be used during testing: in all other cases, using
  StatefulSocket::get_hostname will be preferable. This is because
  StatefulSocket::get_hostname also includes the port, whereas this function
  does not.

     This function does not modify `this` object nor does it throw.
     @snippet StatefulSocket.t.cpp StatefulSocketInitialisesAddrEmpty
     @snippet StatefulSocket.t.cpp StatefulSocketSetGetAddr

     @return a const reference to name.
  **/
  const std::string &get_addr() const noexcept;

  /**
     set_family. This function accepts a `domain` corresponding to a POSIX
  address family and sets the type of this socket to `domain`. As side effects,
  this function will:

     1. Close the socket (if it is open).
     2. Open a new socket with the specified type.

     These side effects are carried out via a call to
  StatefulSocket::make_socket.

     This function returns true in case of success
     and false otherwise. In particular, this function will return false if:

     1. The domain is not AF_INET or AF_INET6.
     2. If opening the new socket or closing the existing socket fails.

     If 1. fails, then the socket is left as before. If 2. fails, then the
  socket will be in an indeterminate state.

     This function does not throw any exceptions.

     @snippet StatefulSocket.t.cpp StatefulSocketFamilyTests
     @param[in] domain: the address family
     @return true if the domain was set correctly, false otherwise.
     @remarks This function essentially mimics manually setting the family of
  the socket. See <a
  href="https://students.mimuw.edu.pl/SO/Linux/Kod/include/linux/socket.h.html">
  this</a> for more information of socket families.
  **/
  bool set_family(const sa_family_t domain) noexcept;

  /**
     is_bound. This function returns true if `this` socket is marked as
     bound to an address and false otherwise. If this function returns true,
     then this socket is bound to a particular IP address and port from which it
  can send and receive data. This function will return false until a successful
  call to StatefulSocket::bind. This function returning true also implies that
  this socket is a server socket: please see the class description for more
  details on this. This function does not modify `this` object and does not
  throw any exceptions.

     @snippet StatefulSocket.t.cpp StatefulSocketStartsUnbound
     @snippet StatefulSocket.t.cpp StatefulSocketBindTests
     @return true if the socket is bound, false otherwise.
  **/
  bool is_bound() const noexcept;

  /**
     is_listening. This function returns true if `this` socket is marked as
  listening and false otherwise. This function will return false if:

     1. The socket is not bound. This can be queried via
  StatefulSocket::is_bound. This happens if the socket is not initialised (see
  StatefulSocket::bind for more).
     2. A successful call to StatefulSocket::listen has not occurred.

     In all other circumstances this will function return true.

     This function does not modify `this` object and does not throw any
  exceptions.
     @snippet StatefulSocket.t.cpp StatefulSocketStartsNotListening
     @snippet StatefulSocket.t.cpp StatefulSocketListens
     @snippet StatefulSocket.t.cpp StatefulSocketListeningFailsIfListenFails
     @return true if the socket is listening, false otherwise.
  **/
  bool is_listening() const noexcept;

  /**
     is_connected. This function returns true if `this` socket is marked as
     connect to an address and false otherwise. If this function returns true,
     then this socket is connected to a particular IP address and port belonging
     to another socket. This function will return false until a successful call
  to StatefulSocket::connect. This function returning true also implies that
  this socket is a client socket: please see the class description for more
  details on this. This function does not modify `this` object and does not
  throw any exceptions.
     @snippet StatefulSocket.t.cpp StatefulSocketInitialisesToUnconnected
     @snippet StatefulSocket.t.cpp StatefulSocketConnectToTests
     @return true if the socket is connected, false otherwise.
  **/
  bool is_connected() const noexcept;

  /**
    is_ip_v6. This function returns true if `this` socket is marked as
   communicating over IPv6 and false otherwise. This function will return false
   until a successful call to either StatefulSocket::set_family with `AF_INET6`
   as the argument, or StatefulSocket::set_ip_v6 has been carried out. This
   function does not throw any exceptions and does not modify `this` object.

    @snippet StatefulSocket.t.cpp StatefulSocketStartsAsNeither
    @snippet StatefulSocket.t.cpp StatefulSocketSetIpv6Tests
    @return true if the socket is marked as IPv6, false otherwise.
   **/
  bool is_ip_v6() const noexcept;

  /**
    is_ip_v4. This function returns true if `this` socket is marked as
  communicating over IPv6 and false otherwise. This function will return false
  until a successful call to either StatefulSocket::set_family() with `AF_INET`
  as the argument, or StatefulSocket::set_ip_v4 has been carried out. This
  function does not throw any exceptions and does not modify `this` object.

    @snippet StatefulSocket.t.cpp StatefulSocketStartsAsNeither
    @snippet StatefulSocket.t.cpp StatefulSocketSetIpv4Tests
    @return true if the socket is marked as IPv6, false otherwise.
  **/
  bool is_ip_v4() const noexcept;

  /**
     set_ip_v4. This function sets the type of this socket to IPv4. This
  function is simply a convenience wrapper around StatefulSocket::set_family.
  This function does not throw and otherwise has all of the same guarantees as
  StatefulSocket::set_family.

     @snippet StatefulSocket.t.cpp StatefulSocketSetIpv4Tests
     @return true if setting the family succeeds, false otherwise.
  **/

  bool set_ip_v4() noexcept;

  /**
     set_ip_v6. This function sets the type of this socket to IPv6. This
  function is simply a convenience wrapper around StatefulSocket::set_family.
  This function does not throw and otherwise has all of the same guarantees as
  StatefulSocket::set_family.

     @snippet StatefulSocket.t.cpp StatefulSocketSetIpv6Tests
     @return true if setting the family succeeds, false otherwise.
  **/
  bool set_ip_v6() noexcept;

  /**
     is_socket_valid. This function returns true if the socket is in a valid
  state. More precisely, this function returns true if the sock member of `this`
  object refers to a valid file descriptor. This function will return false
  until a successful call to one of:
     1. StatefulSocket::set_ip_v6.
     2. StatefulSocket::set_ip_v4.
     3. StatefulSocket::set_family.

     This function does not modify `this` object and this function does not
  throw.
     @snippet StatefulSocket.t.cpp StatefulSocketStartsInvalid
     @snippet StatefulSocket.t.cpp StatefulSocketIsSocketValidTests
     @return true if the socket is valid, false otherwise.
     @remarks This function may modify errno. If errno contains a useful value
  before the call to this function then saving errno beforehand is recommended.
  **/
  bool is_socket_valid() const noexcept;

  /**
     is_connection_valid. This function returns true if this socket has a valid
  connection to another socket. More precisely, this function returns true if
  the `connection` member of `this` socket refers to a valid file descriptor and
  false otherwise. This function will return false until a successful call to
  either: 1) StatefulSocket::accept (in the case of a server), or 2)
  StatefulSocket::connect (in the case of a client).

     This function does not modify `this` object and this function does not
  throw.

     @snippet StatefulSocket.t.cpp StatefulSocketInitialisesToInvalidConnection
     @snippet StatefulSocket.t.cpp StatefulSocketConnectToTests
     @return true if the connection is valid, false otherwise.
     @remarks This function may modify errno. If errno contains a useful value
     before the call to this function then saving errno beforehand is
  recommended.
  **/
  bool is_connection_valid() const noexcept;

  /**
     is_server. This function returns true if this socket represents a server
  connection and false otherwise. For more information on this terminology,
  please see the class level documentation.

     This function does not modify `this` object and this function does not
  throw.
     @snippet StatefulSocket.t.cpp StatefulSocketIsServerByDefault
     @snippet StatefulSocket.t.cpp StatefulSocketClientByOptIn
     @return true if the socket is a server, false otherwise.
  **/
  bool is_server() const noexcept;
  /**
     is_client. This function returns true if this socket represents a client
  connection and false otherwise. For more information on this terminology,
  please see the class level documentation.
     @snippet StatefulSocket.t.cpp StatefulSocketIsServerByDefault
     @snippet StatefulSocket.t.cpp StatefulSocketClientByOptIn
     @return true if the socket is a client, false otherwise.
  **/
  bool is_client() const noexcept;
  /**
     set_addr. This function accepts a hostname `addr` and sets the address of
  this socket to be `addr`. This function returns true in case of success and
  false otherwise.

     More precisely: this function accepts an `addr`, copies `addr` into the
  `name` field of `this` object, and then writes the `addr` to the `ss` field of
  `this` object. If this function fails, then the `name` field of `this` object
  is undefined.

     This function returns false if setting the address fails. This can happen
  if `addr` cannot be converted into a valid network address. This function does
  not throw any exceptions.

     @snippet StatefulSocket.t.cpp StatefulSocketSetAddrTests
     @snippet StatefulSocket.t.cpp StatefulSocketSetGetAddr
     @param[in] addr: the address to set.
     @return true if the function succeeds, false otherwise.
     @remarks This function may modify errno. If errno contains a useful value
  before the call to this function then saving errno beforehand is recommended.
  See <a href="https://man7.org/linux/man-pages/man3/inet_pton.3.html"> this
  </a> for more information.
  **/
  bool set_addr(const std::string &addr) noexcept;

  /**
     set_port. This function accepts a `port` and sets the port of this socket to be `port`.
     This function returns true in case of success and false otherwise.
     This function should only really be used for testing situations where a fixed
     port is needed.
     @param[in] port: the port to be used.
     @return true if successful, false otherwise.
     @remarks This function may modify errno. If errno contains a useful value
  before the call to this function then saving errno beforehand is recommended.
  See <a href="https://man7.org/linux/man-pages/man3/inet_pton.3.html"> this
  </a> for more information.
  **/
  bool set_port(const uint16_t port) noexcept;
  
  /**
     bind. This function binds `this` object's `sock` member to the address set
  via `set_address`, returning true in case of success and false otherwise. This
  function will return `false` until:

     1. A successful call to one of set_ip_v4, set_ip_v6 or set_family has
  occurred.
     2. A successful call to set_addr has occurred.

     This function may still return false if:
     1. The call to POSIX's bind fails. The failure conditions for this are
  described <a href="https://man7.org/linux/man-pages/man2/bind.2.html"> here
  </a>.
     @snippet StatefulSocket.t.cpp StatefulSocketBindTests
     @return true if the binding succeeds, false otherwise.
  **/
  bool bind() noexcept;

  /**
     has_valid_address. This function returns `true` if `this` object's name
  field is not empty and true otherwise. This function will return false unless:
     1. A successful call to StatefulSocket::set_addr has occurred since the
  object was initialised, or
     2. A successful call to StatefulSocket::set_addr has occurred since a
  successful call to one of StatefulSocket::set_ip_v4, StatefulSocket::set_ipv6
  or StatefulSocket::set_family.

     This function does not throw and does not modify `this` object.
     @snippet StatefulSocket.t.cpp StatefulSocketInitialisesWithoutValidAddress
     @snippet StatefulSocket.t.cpp StatefulSocketInvalidAddressFail
     @snippet StatefulSocket.t.cpp StatefulSocketSetGetAddr
     @return true if the `name` field is empty, false otherwise.
  **/
  bool has_valid_address() const noexcept;

  /**
     close. This function closes `this` object's socket if it is open.
     This function is a wrapper around StatefulSocket::close_socket. This
   function returns true in case of success and false otherwise. This function
   will return false if closing the socket fails, or if this function is called
   without a valid socket.

     This function does not throw any exceptions.

     @snippet StatefulSocket.t.cpp StatefulSocketCloseTests

     @return true if closing the socket succeeds, false otherwise.
     @remarks This function may modify errno. If errno contains a useful value
   before the call to this function then saving errno beforehand is recommended.
   We recommend reading <a
   href="https://man7.org/linux/man-pages/man2/close.2.html"> this page </a> for
     more information.
   **/
  bool close() noexcept;

  /**
     listen. This function marks the current
     socket as a client socket. In particular, this function calls the POSIX
  listen function on `this` object's `sock` member with backlog `backlog`.

     This function returns true on success and false otherwise.

     This function will return false if:
     1. This socket is not marked as `bound`. This can be queried via
  StatefulSocket::is_bound. This happens if the socket is not initialised (see
  StatefulSocket::bind for more).
     2. The call to POSIX listen fails.
     3. The `backlog` argument is negative.

     This function does not throw.

     @snippet StatefulSocket.t.cpp StatefulSocketListenTests
     @return true if the call succeeds, false otherwise.

     @remarks This function may modify errno. If errno contains a useful value
  before the call to this function then saving errno beforehand is recommended.
  We recommend reading <a
  href="https://man7.org/linux/man-pages/man2/listen.2.html"> this page </a> for
     more information.
     @remarks This function takes `backlog` as an int, despite the fact that we
  require the value to be non-negative. This is primarily for legacy interaction
  with POSIX's listen.
  **/
  bool listen(const int backlog) noexcept;

  /**
     get_hostname. This function accepts an `out` parameter and writes the
  address of the current socket to it. This consists of writing the full IP
  address to `out`. This function returns true in case of success and false
  otherwise.

     The function will return false if:
     1. The object is not properly initialised.
     2. The socket is not marked as `bound`. This can be queried via
  StatefulSocket::is_bound. This happens if the socket is not initialised (see
  StatefulSocket::bind for more).

     This function does not throw and does not modify `this` object.
     @snippet StatefulSocket.t.cpp StatefulSocketGetHostnameTests
     @snippet StatefulSocket.t.cpp StatefulSocketStartsWithoutHostname
     @param[out] out: the location to write the hostname.
     @return true in case of success, false otherwise.
  **/
  bool get_hostname(std::string &out) const noexcept;

  /**
     accept. This function acts as a wrapper function around the POSIX accept
  function. It extracts the first connection request from the queue of pending
  connections on this object's `sock`, creates a new socket for that connection
  and stores the file descriptor in this object's `connection` member. This
  function returns true in case of success and false otherwise.

     This function returns false if:
     1. This object is not in listening mode. This can be queried via
  StatefulSocket::is_listening. This happens if the socket is not initialised
  (see StatefulSocket::bind for more) and if there has not been a successful
  call to StatefulSocket::listen.
     2. The call to POSIX's accept fails. If this happens, then errno will be
  changed.

     This function does not throw.

     @snippet StatefulSocket.t.cpp StatefulSocketAcceptFailsAtStart
     @snippet StatefulSocket.t.cpp StatefulSocketAcceptTests

     @return true if the function succeeds, false otherwise.

     @remarks This function will block until there is a valid connection.
     This function may modify errno. If errno contains a useful value before
     the call to this function then saving errno beforehand is recommended. We
  recommend reading <a
  href="https://man7.org/linux/man-pages/man2/accept.2.html"> this page </a> for
     more information.
  **/
  virtual bool accept() noexcept;

  /**
     read. This function accepts a `buffer` as input and reads at most
  `read_len` bytes from `this` socket's `connection`. This function returns the
  number of bytes read from the socket. This function returns a negative number
  on an error.

     This function will error if:
     1. The `connection` has not been initialised, either via
  StatefulSocket::connect or StatefulSocket::bind.
     2. If the underlying read fails.
     3. If `len` < 0.
     4. If `buffer` is null.

     This function does not throw.

     @snippet StatefulSocket.t.cpp StatefulSocketReadFailsAtStart
     @snippet StatefulSocket.t.cpp StatefulSocketReadWriteTests

     @param[in] buffer: the buffer to write the data into.
     @param[in] read_len: the maximum number of bytes to read.
     @return the number of bytes read.
     @remarks It is the caller's responsibility to make sure that the buffer is
      large enough to contain `read_len` bytes. We also choose an integer for
  `read_len` (rather than an unsigned int) for compatibility with BoringSSL's
  BIO_read.
  **/
  virtual int read(void *const buffer, const int read_len) noexcept;

  /**
     write. This function accepts a `buffer` as input and writes at most
   `write_len` bytes to `this` socket's `connection`. This function returns true
   if the write is successful and false otherwise.

     This function will error if:
     1. The `connection` has not been initialised, either via
   StatefulSocket::connect_to or StatefulSocket::bind.
     2. If the underlying write fails.

     This function does not throw.

     @snippet StatefulSocket.t.cpp StatefulSocketWriteFailsAtStart
     @snippet StatefulSocket.t.cpp StatefulSocketReadWriteTests

     @param[in] buffer: the buffer to write the data from.
     @param[in] write_len: the maximum number of bytes to write.
     @param[out] ret_code: an optional parameter for writing the return code
     of the underlying writing function. This is not used in the default
     implementation of this function.
     @return true if the write was successful, false otherwise.
     @remarks It is the caller's responsibility to make sure that the buffer
   contains at least `write_len` bytes. We also choose std::size_t for
   `write_len` (rather than an int) for compatibility with BoringSSL's
   BIO_write_all.
   **/
  virtual bool write(const void *const buffer, const std::size_t write_len,
                     int *const ret_code = nullptr) noexcept;

  /**
     connect_to. This function connects `this` socket to the socket bound to
   `address` at port `port_number`. This function returns true in case of
   success and false otherwise.

     This function will fail if:

     1. The supplied address is empty.
     2. A successful call to StatefulSocket::set_family,
   StatefulSocket::set_ip_v4 or StatefulSocket::set_ip_v6 has not yet occurred.
     3. If the address is not a valid IP address.
     4. If the connection fails.

     @snippet StatefulSocket.t.cpp StatefulSocketConnectToTests

     @param[in] address: the IP address to connect to.
     @param[in] port_number: the port number to connect to.
     @return true in case of success, false otherwise.
   **/

  virtual bool connect_to(const std::string &address,
                          const uint16_t port_number);

  /**
     get_portnumber. This function writes a copy of `this` socket's port number
  to the `out` parameter. This function returns true when successful and false
  otherwise.

     This function will fail unless:
     1) There has been a successful binding (see StatefulSocket::bind for more).
     2) The out pointer is non-null.


     This function does not modify `this` object and does not throw.

     @snippet StatefulSocket.t.cpp StatefulSocketGetPortNumberFailsAtStart
     @snippet StatefulSocket.t.cpp StatefulSocketPortNumberv6
     @snippet StatefulSocket.t.cpp StatefulSocketPortNumberv4
     @snippet StatefulSocket.t.cpp StatefulSocketGetPortNumberTests
     @param[out] out: the location to write the port number.
     @return true on success, false otherwise.
  **/
  bool get_portnumber(uint16_t *const out) const noexcept;

  /**
     get_bio. This function releases the pointer contained in
   StatefulSocket::bio_wrapper and returns the pointer to the caller. This has
   side-effects.

     1. `this` socket will not be able to use StatefulSocket::read or
   StatefulSocket::write after the call to this function.
     2. `this` socket will no longer manage the lifetime of the underlying
   object.

     This function will return a null pointer unless:

     1. a successful call to StatefulSocket::accept has occurred, or
     2. a successful call to StatefulSocket::connect has occurred, or
     3. StatefulSocket::get_bio has not yet been called.

     This function does not throw any exceptions.

     @snippet StatefulSocket.t.cpp StatefulSocketGetBioReturnsNullAtStart
     @snippet StatefulSocket.t.cpp StatefulSocketGetBioTests

     @return a pointer to a BIO* object.

   **/
  BIO *get_bio() noexcept;

private:
  /**
     set_bio. This function wraps the `connection` file descriptor in a
     BIO. This is so that we can take advantage of BoringSSL's BIO_read and
     BIO_write functions. This function returns true in case of success and
  false otherwise.

     This function returns false if setting the BIO fails. This function does
  not throw any exceptions.

     @return true if creating the BIO succeeds, false otherwise.
     @remarks The created BIO does not manage the lifetime
     file descriptor: this is so that the SSL context doesn't close the file
  descriptor before the socket has gone out of scope.
  **/
  bool set_bio() noexcept;

  /**
     close_socket. This function accepts a file descriptor `sock` and
     closes it. This function is just a wrapper around ::close on POSIX
     systems. This function does not throw any exceptions.

     @param[in] sock: the file descriptor.
     @return 0 in case of success, -1 otherwise. If -1 is returned, then errno
  is modified.
     @remarks This function may modify errno. If errno contains a useful value
  before the call to this function then saving errno beforehand is recommended.
  We recommend reading <a
  href="https://man7.org/linux/man-pages/man2/close.2.html"> this page </a> for
     more information.
  **/
  static int close_socket(const int sock) noexcept;

  /**
     make_socket. This function opens a new socket and stores the file
  descriptor in the `in_sock` argument. If `in_sock` refers to an existing
  file descriptor, then this function calls close on `in_sock`
  before creating a new file descriptor.

     This function returns true if the function is successful
     and false otherwise.

     This function will return false if
     1. Closing the open socket fails, if applicable.
     2. Creating the file descriptor fails.

     This function does not throw.

     @return true if the function is successful, false otherwise.
  **/
  bool make_socket(int &in_sock) noexcept;

  /**
     make_socket. This function opens a new socket and stores the file
  descriptor in `this` object's `sock` field. If `sock` refers to an existing
  file descriptor, then this function calls StatefulSocket::close_socket on
  `sock` before creating a new file descriptor.

     This function returns true if the function is successful
     and false otherwise.

     This function will return false if
     1. Closing the open socket fails, if applicable.
     2. Creating the file descriptor fails.

     This function does not throw.

     @return true if the function is successful, false otherwise.
  **/
  bool make_socket() noexcept;

  /**
     is_socket_valid. This function returns true if the socket is in a valid
  state. More precisely, this function returns true if the sock member of `this`
  object refers to a valid file descriptor. This function will return false
  until a successful call to one of:
     1. StatefulSocket::set_ip_v6.
     2. StatefulSocket::set_ip_v4.
     3. StatefulSocket::set_family.

     @snippet StatefulSocket.t.cpp StatefulSocketStartsInvalid
     @snippet StatefulSocket.t.cpp StatefulSocketIsSocketValidTests

     This function does not modify `this` object and this function does not
  throw.
     @return true if the socket is valid, false otherwise.
     @remarks This function may modify errno. If errno contains a useful value
  before the call to this function then saving errno beforehand is recommended.
  **/
  bool is_socket_valid(const int sock_in) const noexcept;
};

#endif

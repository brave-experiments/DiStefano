#ifndef INCLUDED_TLSSOCKET_HPP
#define INCLUDED_TLSSOCKET_HPP

#include "StatefulSocket.hpp"      // Needed for the underlying Socket.
#include "ThreePartyHandshake.hpp" // Needed for TLS attestation things.

/**
   @brief TLSSocket. This class acts as a wrapper around StatefulSocket, but
with a binding to a SSL object. This is primarily to ensure that the lifetime of
the SSL object (along with the file descriptor) is bound to a more
strongly-scoped object.

   This class is actually a rather small wrapper around the much larger
StatefulSocket. To reduce the code bloat here, we publicly inherit from
StatefulSocket. This allows most of StatefulSocket's operations to be used here
too, and we only need to override certain functionality to enable the messages
to be encrypted.
**/
class TLSSocket : public StatefulSocket {
public:
  /**
     ~TLSSocket. This destructor simply frees the TLSSocket::ssl member and then
  delegates to the parent destructor. This destructor does not throw unless
  SSL_free throws. Please note that prior to `this` TLSSocket going out of scope
  TLSSocket::Shutdown should be called.
  **/
  ~TLSSocket() noexcept(noexcept(SSL_free)) override;

  /**
     TLSSocket. This constructor creates a new TLSSocket. In particular, this
  function takes a non-owning pointer to a `ssl_ctx` and initialises a new SSL
  object along using the `ssl_ctx`.

     This function does not throw. Instead, if ssl is constructed improperly
     then the `ssl` pointer will be null. This can be checked via
  TLSSocket::is_ssl_valid. In case of error, the best way to fix this is to
  check the underlying context and, if there's a problem, then create a new
  TLSSocket with a fixed version of the context. For example, a failure case
  would be to pass in a null context to this function.

     @snippet TLSSocket.t.cpp TLSSocketConstructorTests
     @param[in] ssl_ctx: a non-owning pointer to the parent ssl_ctx.
     @param[in] is_server: denotes if this TLSSocket is a server or a client
  socket.
  **/
  TLSSocket(SSL_CTX *const ssl_ctx, const bool is_server = true);

  /**
     TLSSocket. This constructor creates a new TLSSocket. In particular, this
  function takes a non-owning reference to a `ssl_ctx` and initialises a new SSL
  object along using the `ssl_ctx`.

     This function does not throw. Instead, if ssl is constructed improperly
     then the `ssl` pointer will be null. This can be checked via
  TLSSocket::is_ssl_valid. In case of error, the best way to fix this is to
  check the underlying context and, if there's a problem, then create a new
  TLSSocket with a fixed version of the context.

     @snippet TLSSocket.t.cpp TLSSocketConstructorTests
     @param[in] ssl_ctx: a non-owning reference to the parent ssl_ctx.
     @param[in] is_server: denotes if this TLSSocket is a server or a client
  socket.
  **/
  TLSSocket(SSL_CTX &ssl_ctx, const bool is_server = true);

  /**
     is_ssl_valid. This function returns false if `this` socket's `ssl` member
     is a null pointer and true otherwise. Put differently, this function
  returns true if `this` socket contains a valid `ssl` object and false
  otherwise. This is similar to checking whether this `socket` is in a valid
  state.

     This function does not throw or modify this object.
     @return true if `this` socket's `ssl` member is non-null, false otherwise.
  **/
  bool is_ssl_valid() const noexcept;

  /**
     read. This function reads at most `read_len` bytes from `this` socket's
     TLSSocket::ssl object into the `buffer` and returns the number of bytes
     that we read. This function returns an integer <= 0 if an error occurs.

     This function will return <= 0 if:
     1. The connection has not yet been initialised.
     2. If reading from the ssl object fails.

     If an error occurs, then calling TLSSocket::get_ssl_error immediately after
   this call will produce the requisite BoringSSL error code. This can then be
   used to determine how to proceed.

     This function does not throw.

     @param buffer: the buffer into which the read bytes are written.
     @param[in] read_len: the maximum number of bytes to read.
     @return the number of read bytes. This is less than 0 in case of error.

     @remarks This function as the same side-effects as BoringSSL's SSL_read.
   This function also requires the caller to ensure that `buffer` is big enough
   to hold at least `read_len` bytes.
   **/
  int read(void *const buffer, const int read_len) noexcept override;

  /**
     peek. This function is a wrapper around BoringSSL's peek() function.
     This function returns the number of bytes waiting in this socket's
     message.
  **/
  int peek(void *const buffer, const int read_len) noexcept;

  /**
     get_ssl_error. This function accepts a `return_code` and returns the
  BoringSSL error code associated with that return code (if any). This is code
  is contextual: it depends on the state of `this` socket's ssl member.

     In implementation, this function simply delegates to BoringSSL's
  SSL_get_error.

     This function does not throw or modify `this` object.

     @snippet TLSSocket.t.cpp TLSSocketGetSSLErrorTests

     @param[in] return_code: the return code from the SSL operation.
     @return the BoringSSL error associated with that error code.
  **/
  int get_ssl_error(const int return_code) const noexcept;

  /**
     write. This function writes at most `write_len` bytes from `buffer` to
    `this` socket's TLSSocket::ssl object. This function returns true if the
    number of written bytes were equal to `write_len` and false otherwise.

     This function will return false if:
     1. The connection has not yet been initialised.
     2. Writing to the ssl object fails.
     3. `write_len` > SSL3_RT_MAX_PLAIN_LENGTH.
     4. `write_len` == 0.

     If an error occurs, then calling TLSSocket::get_ssl_error with `ret_code`
    immediately after this call will produce the requisite BoringSSL error code.
    This can then be used to determine how to proceed.

     This function does not throw.

     @snippet TLSSocket.t.cpp TLSSocketWritePreconditionTests
     @snippet TLSSocket.t.cpp TLSSocketReadWriteTests

     @param buffer: the buffer containing the bytes to be written.
     @param[in] write_len: the maximum number of bytes to written.
     @param[out] ret_code: the return code from SSL_write. If this is null,
     then no code is written.
     @return true in case of success, false otherwise.

     @remarks This function as the same side-effects as BoringSSL's SSL_write.
    This function also requires the caller to ensure that `buffer` contains a
    valid message.
    **/
  bool write(const void *const buffer, const std::size_t write_len,
             int *const ret_code = nullptr) noexcept override;

  /**
     accept. This function is a wrapper function around StatefulSocket::accept.
     The only difference between this function and StatefulSocket::accept is
  that this function immediately transfers ownership of the underlying BIO
  (retrieved via StatefulSocket::get_bio) to the SSL object. This function will
  return true if successful and false otherwise.

     This function will return false if:
     1. StatefulSocket::accept fails.

     This function does not throw.
     @snippet TLSSocket.t.cpp TLSSocketAcceptTests
     @return true in case of success, false otherwise.
  **/
  bool accept() noexcept override;

  /**
     do_handshake. This function acts as a wrapper for the server to do a
  handshake. In particular, this function passes ownership of the underlying BIO
  (retrieved via StatefulSocket::get_bio) to the underlying SSL object. This
  function then calls SSL_accept to carry out the handshake, returning the
  result.

     This function will return 1 in the case of success, and a different value
  otherwise. In particular:
     1. If `this` socket corresponds to a client, SSL_ERROR_WANT_CONNECT will be
  returned.
     2. If `this` socket has not yet called StatefulSocket::Accept then
  SSL_ERROR_WANT_ACCEPT will be returned.
     3. Otherwise, the result of calling SSL_accept will be returned.

     @snippet TLSSocket.t.cpp TLSSocketDoHandshakeTests
     @snippet TLSSocket.t.cpp TLSSocketConnectToTests
     This function does not throw.
     @return 1 in the case of success, any other integer otherwise.
  **/
  int do_handshake() noexcept;

  /**
     pending. This function returns the number of pending bytes on `this`
  socket. This is primarily useful for preventing us from overwriting bytes that
  are waiting to be read. This function does not throw.

     @return the number of bytes that are pending.
  **/
  int pending() noexcept;

  /**
     connect_to. This function acts as a wrapper function around
   StatefulSocket::connect_to. If StatefulSocket::connect_to fails, then this
   function returns false. Otherwise, this function calls
   StatefulSocket::get_bio and passes ownership of the retrieved BIO to
   TLSSocket::ssl. This function will also initiate a new SSL connection with
   the other socket.


     In other words, this function
     operates like the normal StatefulSocket::connect_to function, but it
   adjusts the ownership of the BIO slightly and also does a SSL handshake.

     This is primarily to make sure that the SSL object has total control over
   the underlying stream and is in a valid state.

     @snippet TLSSocket.t.cpp TLSSocketConnectToTests
     @param[in] address: the IP address to connect to.
     @param[in] port_number: the port number to connect to.
     @return true if StatefulSocket::connect_to, the ownership transfer and the
   handshake succeed, false otherwise.
   **/
  bool connect_to(const std::string &address,
                  const uint16_t port_number) override;

  /**
     set_handshake_callback. This function sets the handshake callback function
  for the underlying ssl object to `cb`. If `cb` is not a null pointer, then the
  function `cb` will be called after `this` socket has generated key shares for
  an SSL connection with another node.

     This function returns true in case of success or false
     otherwise.

     This function will return false if:
     1. This socket is not a client socket.

     This function does not throw.

     @snippet TLSSocket.t.cpp TLSSocketCannotSetServerCallback

     @param[in] cb: the callback function.
     @return true if setting is successful, false otherwise.
     @remarks Note that `cb` may be a null pointer. The code in BoringSSL is
  responsible for checking this prior to a dereference.
  **/
  bool set_handshake_callback(
      ThreePartyHandshake::handshake_function_type cb =
          &ThreePartyHandshake::three_party_handshake_comm) noexcept;

  /**
     get_handshake_callback. This function returns a copy of the handshake
  callback function pointer in `this` socket's ssl object. The impact of
  returning a copy is that modifying the returned value does not modify the
  function pointer held by the underlying `ssl` object: to change this, call
  TLSSocket::set_handshake_callback instead.

     This function will return a null pointer if:
     1. `this` socket is not a client socket.
     2. A successful call to set_handshake_callback has not yet occurred. This
  is because a null callback function is the default.
     3. `this` socket is not initialised properly. This can be queried via
  TLSSocket::is_ssl_valid.

     This function does not throw and does not modify `this` object.
     @return a copy of the handshake callback function pointer held by `this`
  socket.
  **/
  ThreePartyHandshake::handshake_function_type
  get_handshake_callback() const noexcept;

  /**
     set_keyshare_callback. This function sets the keyshare callback function
  for the underlying ssl object to `cb`. If `cb` is not a null pointer, then the
  function `cb` will be called after `this` socket has generated key shares for
  an SSL connection with another node.

     This function returns true in case of success or false
     otherwise.

     This function will return false if:
     1. This socket is not a client socket.

     This function does not throw.

     @snippet TLSSocket.t.cpp TLSSocketSetHandshakeCallbackTests

     @param[in] cb: the callback function.
     @return true if setting is successful, false otherwise.
     @remarks Note that `cb` may be a null pointer. The code in BoringSSL is
  responsible for checking this prior to a dereference.
  **/
  bool set_keyshare_callback(
      ThreePartyHandshake::send_key_share_function_type cb =
          &ThreePartyHandshake::
              three_party_handshake_send_received_key_shares) noexcept;

  /**
     set_derive_shared_secret_callback. This function sets the
  derive_shared_secret callback function for the underlying ssl object to `cb`.
  If `cb` is not a null pointer, then the function `cb` will be called after
  `this` socket has generated key shares for an SSL connection with another
  node.

     This function returns true in case of success or false
     otherwise.

     This function will return false if:
     1. This socket is not a client socket.

     This function does not throw.

     @param[in] cb: the callback function.
     @return true if setting is successful, false otherwise.
     @remarks Note that `cb` may be a null pointer. The code in BoringSSL is
  responsible for checking this prior to a dereference.
  **/
  bool set_derive_shared_secret_callback(
      ThreePartyHandshake::derive_shared_secret_function_type cb =
          &ThreePartyHandshake::derive_handshake_secret) noexcept;

  /**
     set_derive_handshake_secrets_callback. This function sets the
  derive_handshake_secret callback function for the underlying ssl object to
  `cb`. If `cb` is not a null pointer, then the function `cb` will be called
  after `this` shocket has generated the shared x co-ordinate for an SSL
  connection with another node. This function returns true in case of success
  and false otherwise. This function will return false if:
     1. This socket is not a client socket.

     This function does not throw.

     @param[in] cb: the callback function.
     @return true if setting is successful, false otherwise.
     @remarks Note that `cb` may be a null pointer. The code in BoringSSL is
  responsible for checking this prior to a dereference.
  **/
  bool set_derive_handshake_keys_callback(
      ThreePartyHandshake::derive_handshake_keys_function_type cb =
          &ThreePartyHandshake::derive_handshake_keys) noexcept;

  /**
     set_derive_traffic_secrets_callback. This function sets the
  derive_traffic_secret callback function for the underlying ssl object to
  `cb`. If `cb` is not a null pointer, then the function `cb` will be called
  after `this` socket has committed to (and verified) the certificate from
  another server. connection with another node. This function returns true in
  case of success and false otherwise. This function will return false if:
     1. This socket is not a client socket.

     This function does not throw.

     @param[in] cb: the callback function.
     @return true if setting is successful, false otherwise.
     @remarks Note that `cb` may be a null pointer. The code in BoringSSL is
  responsible for checking this prior to a dereference.
  **/
  bool set_derive_traffic_keys_callback(
      ThreePartyHandshake::derive_traffic_keys_function_type cb =
          &ThreePartyHandshake::derive_traffic_keys) noexcept;

  /**
     set_commit_to_server_certificate_callback. This function sets the
  commit_to_server_certificate function for the underlying ssl object to
  `cb`. If `cb` is not a null pointer, then the function `cb` will be called
  after `this` socket has derived handshake keys.
  This function returns true in case of success and false otherwise. This
  function will return false if:
     1. This socket is not a client socket.

     This function does not throw.

     @param[in] cb: the callback function.
     @return true if setting is successful, false otherwise.
     @remarks Note that `cb` may be a null pointer. The code in BoringSSL is
  responsible for checking this prior to a dereference.
  **/
  bool set_commit_to_server_certificate_callback(
      ThreePartyHandshake::commit_to_server_certificate_function_type cb =
          &ThreePartyHandshake::commit_to_server_certificate) noexcept;

  /**
     get_keyshare_callback. This function returns a copy of the keyshare
  callback function pointer in `this` socket's ssl object. The impact of
  returning a copy is that modifying the returned value does not modify the
  function pointer held by the underlying `ssl` object: to change this, call
  TLSSocket::set_handshake_callback instead.

     This function will return a null pointer if:
     1. `this` socket is not a client socket.
     2. A successful call to set_keyshare_callback has not yet occurred. This
  is because a null callback function is the default.
     3. `this` socket is not initialised properly. This can be queried via
  TLSSocket::is_ssl_valid.

     This function does not throw and does not modify `this` object.
     @return a copy of the handshake callback function pointer held by `this`
  socket.
  **/
  ThreePartyHandshake::send_key_share_function_type
  get_keyshare_callback() const noexcept;

  /**
     get_ssl_object. This function returns a pointer to `this` socket's SSL
  object. This is done by copying `this` sockets's ssl pointer.

     Please note that:
     1. This is dangerous. The returned pointer can be modified directly. This
  allows a caller to violate the invariants related to `this` object.
     2. No reference counting is increased. This means that the returned pointer
  may go out of scope.

     As a result, this function should only be used in testing.

     This function does not throw.
     @return a pointer to `this` socket's SSL object.
     @remarks This function will never return a null pointer on a valid object.
  **/
  SSL *get_ssl_object() noexcept;

  /**
     set_ssl_certificate. This function sets the `certificate` for `this` ssl
  connection, returning true in the case of success and false otherwise. This
  function is useful if the certificate has changed since `this` socket was
  created.

     This function returns false if:
     1. `certificate` is null.
     2. setting the certificate fails internally.

     This function does not throw.
     @snippet TLSSocket.t.cpp TLSSocketSettingCertificateWorks
     @param[in] certificate: the certificate to use.
     @return true in case of success, false otherwise.
  **/
  bool set_ssl_certificate(X509 *const certificate) noexcept;

  /**
     set_verifier_conneciton. This function sets the `verifier` field for `this`
     SSL connection, returning true in case of success and false otherwise.
     This function is used for creating outbound hooks for certain operations.
     This function returns false if:

     1. `this` socket is not a client socket.
     2. setting the `verifier` fails.

     This function does not throw.

     @snippet TLSSocket.t.cpp TLSSocketSettingVerifierConnectionWorks
     @return true in case of success, false otherwise.
     @remarks The `verifier` pointer may be null. This corresponds to unhooking
     an outbound hook.
  **/
  bool set_verifier_connection(SSL *const verifier) noexcept;

  bool set_write_h6_callback(ThreePartyHandshake::write_h6_function_type cb =
                                 &ThreePartyHandshake::write_h6) noexcept;

  bool set_derive_gcm_shares_callback(
      ThreePartyHandshake::derive_gcm_shares_function_type cb =
          &ThreePartyHandshake::derive_gcm_shares) noexcept;

  /**
     get_verifier_connection. This function retrieves the `verifier` field for
  `this` SSL connection. In particular, this function returns a non-const
  pointer to a SSL object. This function is mostly used for testing. This
  function will return nullptr if:

     1. If `this` socket is a server socket.
     2. If `this` socket does not have a valid verifier set.

     This function does not throw.
     @snippet TLSSocket.t.cpp TLSSocketGetVerifierConnectionWorks
     @return a pointer to an SSL object.
  **/
  SSL *get_verifier_connection() noexcept;

  /**
     set_make_circuits. This function sets `this` SSL connection to make
  circuits during key establishment. This is used in all non-test code, as we
  allow the caller to not build circuits during tests to make their execution
  faster. This function does not throw.
  **/
  void set_make_circuits() noexcept;

private:
  /**
     ssl. This field contains the SSL connection for this socket. This object is
  used to deal with all cryptographic operations that occur inside this socket.
  Note that this object is owned by `this` socket: when this socket is
  destroyed, the TLSSocket::ssl field is freed.
  **/
  SSL *ssl;
};

#endif

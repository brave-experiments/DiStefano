#include "TLSSocket.hpp"
#include "openssl/ssl.h"
#include <iostream>
#include <thread>

SSL *TLSSocket::get_verifier_connection() noexcept { return ssl->verifier; }

bool TLSSocket::set_verifier_connection(SSL *const verifier) noexcept {
  if (is_server()) {
    return false;
  }

  this->ssl->verifier = verifier;
  return true;
}

TLSSocket::~TLSSocket() noexcept(noexcept(SSL_free)) { SSL_free(ssl); }

TLSSocket::TLSSocket(SSL_CTX &ssl_ctx, const bool is_server)
    : StatefulSocket(is_server), ssl{SSL_new(&ssl_ctx)} {}

TLSSocket::TLSSocket(SSL_CTX *const ssl_ctx, const bool is_server)
    : StatefulSocket{is_server}, ssl{SSL_new(ssl_ctx)} {}

bool TLSSocket::set_ssl_certificate(X509 *const certificate) noexcept {
  if (!certificate) {
    return false;
  }

  return SSL_use_certificate(ssl, certificate);
}

int TLSSocket::read(void *const buffer, const int read_len) noexcept {
  return SSL_read(ssl, buffer, read_len);
}

int TLSSocket::peek(void *const buffer, const int max_len) noexcept {
  return SSL_peek(ssl, buffer, max_len);
}

int TLSSocket::pending() noexcept { return SSL_pending(ssl); }

bool TLSSocket::write(const void *const buffer, const std::size_t write_len,
                      int *const ret_code) noexcept {

  // Cannot write too much in one go.
  if (write_len > SSL3_RT_MAX_PLAIN_LENGTH || write_len == 0) {
    return false;
  }

  // NOTE: this cast is fine. This is because:
  // 1) SSL3_RT_MAX_PLAIN_LENGTH is much less than the maximum positive value
  // stored in an int on all systems. See
  // https://www.open-std.org/JTC1/SC22/WG14/www/docs/n1256.pdf for INT_MAX.
  // Whilst this is from the C standard, C++ draws on this fact. 2) We know that
  // SSL3_RT_MAX_PLAIN_LENGTH is the maximum value we'll pass here because of
  // the check above.
  const auto write_amount = SSL_write(ssl, buffer, static_cast<int>(write_len));
  if (ret_code) {
    *ret_code = write_amount;
  }

  // Same reasoning as above for why this cast is fine.
  return write_amount == static_cast<int>(write_len);
}

static bool set_bio_impl(SSL *ssl, BIO *bio) {
  SSL_set_bio(ssl, bio, bio);
  return true;
}

bool TLSSocket::connect_to(const std::string &address,
                           const uint16_t port_number) {
  if (!StatefulSocket::connect_to(address, port_number)) {
    return false;
  }

  set_bio_impl(ssl, StatefulSocket::get_bio());
  return SSL_connect(ssl) > 0;
}

bool TLSSocket::accept() noexcept {
  // The only difference between this function and StatefulSocket's accept
  // is that we transfer the BIO ownership over to the SSL object here.
  return StatefulSocket::accept() &&
         set_bio_impl(ssl, StatefulSocket::get_bio());
}

int TLSSocket::get_ssl_error(const int return_code) const noexcept {
  return SSL_get_error(ssl, return_code);
}

int TLSSocket::do_handshake() noexcept {
  if (is_client()) {
    // This seems like the most sensible outcome here
    // This is because this is what we might expect from a client
    return SSL_ERROR_WANT_CONNECT;
  }

  if (!is_connection_valid()) {
    // We've not had a call to ACCEPT yet: so,
    // that should happen first.
    return SSL_ERROR_WANT_ACCEPT;
  }

  return SSL_accept(ssl);
}

bool TLSSocket::set_handshake_callback(
    ThreePartyHandshake::handshake_function_type cb) noexcept {
  // This check needs some explaining.
  // This function can be called at any time -- even before do_handshake or
  // accept. As a result, even if this socket has a type, it isn't guaranteed
  // that `ssl` knows this fact. This means that the call to
  // SSL::set_commit_to_key_shares might not fail here, when it should. To get
  // around this, we do this check ahead of time to stop the socket from falling
  // into a state that isn't supported.
  if (is_server()) {
    return false;
  }
  return SSL::set_commit_to_key_shares(ssl, cb);
}

bool TLSSocket::set_derive_shared_secret_callback(
    ThreePartyHandshake::derive_shared_secret_function_type cb) noexcept {
  // This check needs some explaining.
  // This function can be called at any time -- even before do_handshake or
  // accept. As a result, even if this socket has a type, it isn't guaranteed
  // that `ssl` knows this fact. This means that the call to
  // SSL::set_* might not fail here, when it should. To get
  // around this, we do this check ahead of time to stop the socket from falling
  // into a state that isn't supported.
  if (is_server()) {
    return false;
  }

  return SSL::set_derive_secret_share(ssl, cb);
}

bool TLSSocket::set_derive_handshake_keys_callback(
    ThreePartyHandshake::derive_handshake_keys_function_type cb) noexcept {
  // This check needs some explaining.
  // This function can be called at any time -- even before do_handshake or
  // accept. As a result, even if this socket has a type, it isn't guaranteed
  // that `ssl` knows this fact. This means that the call to
  // SSL::set_* might not fail here, when it should. To get
  // around this, we do this check ahead of time to stop the socket from falling
  // into a state that isn't supported.
  if (is_server()) {
    return false;
  }

  return SSL::set_derive_handshake_keys(ssl, cb);
}

bool TLSSocket::set_derive_traffic_keys_callback(
    ThreePartyHandshake::derive_traffic_keys_function_type cb) noexcept {
  // This check needs some explaining.
  // This function can be called at any time -- even before do_handshake or
  // accept. As a result, even if this socket has a type, it isn't guaranteed
  // that `ssl` knows this fact. This means that the call to
  // SSL::set_* might not fail here, when it should. To get
  // around this, we do this check ahead of time to stop the socket from falling
  // into a state that isn't supported.
  if (is_server()) {
    return false;
  }

  return SSL::set_derive_traffic_keys(ssl, cb);
}

bool TLSSocket::is_ssl_valid() const noexcept { return ssl != nullptr; }

bool TLSSocket::set_keyshare_callback(
    ThreePartyHandshake::send_key_share_function_type cb) noexcept {
  // This check needs some explaining.
  // This function can be called at any time -- even before do_handshake or
  // accept. As a result, even if this socket has a type, it isn't guaranteed
  // that `ssl` knows this fact. This means that the call to
  // SSL::set_* might not fail here, when it should. To get
  // around this, we do this check ahead of time to stop the socket from falling
  // into a state that isn't supported.
  if (is_server()) {
    return false;
  }

  return SSL::set_send_key_shares(ssl, cb);
}

bool TLSSocket::set_commit_to_server_certificate_callback(
    ThreePartyHandshake::commit_to_server_certificate_function_type
        cb) noexcept {
  // This check needs some explaining.
  // This function can be called at any time -- even before do_handshake or
  // accept. As a result, even if this socket has a type, it isn't guaranteed
  // that `ssl` knows this fact. This means that the call to
  // SSL::set_* might not fail here, when it should. To get
  // around this, we do this check ahead of time to stop the socket from falling
  // into a state that isn't supported.
  if (is_server()) {
    return false;
  }

  return SSL::set_commit_to_server_certificate(ssl, cb);
}

bool TLSSocket::set_write_h6_callback(
    ThreePartyHandshake::write_h6_function_type cb) noexcept {
  // This check needs some explaining.
  // This function can be called at any time -- even before do_handshake or
  // accept. As a result, even if this socket has a type, it isn't guaranteed
  // that `ssl` knows this fact. This means that the call to
  // SSL::set_* might not fail here, when it should. To get
  // around this, we do this check ahead of time to stop the socket from falling
  // into a state that isn't supported.
  if (is_server()) {
    return false;
  }

  return SSL::set_write_h6(ssl, cb);
}

bool TLSSocket::set_derive_gcm_shares_callback(
    ThreePartyHandshake::derive_gcm_shares_function_type cb) noexcept {
  // This check needs some explaining.
  // This function can be called at any time -- even before do_handshake or
  // accept. As a result, even if this socket has a type, it isn't guaranteed
  // that `ssl` knows this fact. This means that the call to
  // SSL::set_* might not fail here, when it should. To get
  // around this, we do this check ahead of time to stop the socket from falling
  // into a state that isn't supported.
  if (is_server()) {
    return false;
  }

  return SSL::set_derive_gcm_shares(ssl, cb);
}

ThreePartyHandshake::send_key_share_function_type
TLSSocket::get_keyshare_callback() const noexcept {
  if (!ssl) {
    return nullptr;
  }

  return ssl->send_key_shares;
}

ThreePartyHandshake::handshake_function_type
TLSSocket::get_handshake_callback() const noexcept {
  if (!ssl) {
    return nullptr;
  }

  return ssl->commit_to_key_shares;
}

SSL *TLSSocket::get_ssl_object() noexcept { return ssl; }

void TLSSocket::set_make_circuits() noexcept {
  assert(ssl);
  ssl->should_make_circuits = true;
}

#include "EmpSSLSocketManager.hpp"
#include "ThreadSafeSSL.hpp" // This should have everything we need in it.

// This is the file-local socket variable that we use for SSL communications
// with the client. This must be initialised via the appropriate create_ssl
// function and destroyed via the appropriate destroy_ssl function.
static ThreadSafeSSL *client_socket{nullptr};
static ThreadSafeSSL *server_socket{nullptr};

template <bool is_server> static void create_ssl(SSL *const ssl) noexcept {
  assert(ssl);
  if (is_server) {
    assert(server_socket == nullptr);
    server_socket = new ThreadSafeSSL(ssl);
  } else {
    assert(client_socket == nullptr);
    client_socket = new ThreadSafeSSL(ssl);
  }
}

template <bool is_server> static void destroy_ssl() noexcept {
  if (is_server) {
    delete server_socket;
    server_socket = nullptr;
  } else {
    delete client_socket;
    client_socket = nullptr;
  }
}

ThreadSafeSSL *EmpSSLSocketManager::get_ssl_server() noexcept {
  return server_socket;
}

ThreadSafeSSL *EmpSSLSocketManager::get_ssl_client() noexcept {
  return client_socket;
}

void EmpSSLSocketManager::destroy_ssl_server() noexcept { destroy_ssl<true>(); }

void EmpSSLSocketManager::destroy_ssl_client() noexcept {
  destroy_ssl<false>();
}

void EmpSSLSocketManager::create_ssl_client(SSL *const ssl) noexcept {
  create_ssl<false>(ssl);
}

void EmpSSLSocketManager::create_ssl_server(SSL *const ssl) noexcept {
  create_ssl<true>(ssl);
}

unsigned EmpSSLSocketManager::register_new_socket_server() noexcept {
  assert(server_socket);
  return server_socket->register_new_socket();
}

unsigned EmpSSLSocketManager::register_new_socket_client() noexcept {
  assert(client_socket);
  return client_socket->register_new_socket();
}

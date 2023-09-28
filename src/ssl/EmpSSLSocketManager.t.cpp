#include "../doctest.h"
#include "EmpSSLSocketManager.hpp"
#include "TestUtil.hpp"

//! [EmpSSLSocketManagerDefaults]
TEST_CASE("defaults") {
  // These should be true.
  CHECK(EmpSSLSocketManager::get_ssl_client() == nullptr);
  CHECK(EmpSSLSocketManager::get_ssl_server() == nullptr);
}
//! [EmpSSLSocketManagerDefaults]

//! [EmpSSLSocketManagerCreateSSL]
TEST_CASE("e2e") {
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  REQUIRE(ssl);

  //! [EmpSSLSocketManagerCreateSSL]
  EmpSSLSocketManager::create_ssl_client(ssl.get());
  CHECK(EmpSSLSocketManager::get_ssl_client() != nullptr);
  CHECK(EmpSSLSocketManager::get_ssl_server() == nullptr);

  EmpSSLSocketManager::create_ssl_server(ssl.get());
  CHECK(EmpSSLSocketManager::get_ssl_server() != nullptr);
  CHECK(EmpSSLSocketManager::get_ssl_client() !=
        EmpSSLSocketManager::get_ssl_server());
  //! [EmpSSLSocketManagerCreateSSL]

  //! [EmpSSLSocketManagerRegisterNewSocket]
  for (unsigned i = 0; i < 100; i++) {
    CHECK(EmpSSLSocketManager::register_new_socket_client() == i);
    CHECK(EmpSSLSocketManager::register_new_socket_server() == i);
  }
  //! [EmpSSLSocketManagerRegisterNewSocket]

  //! [EmpSSLSocketManagerDestroySSL]
  EmpSSLSocketManager::destroy_ssl_client();
  CHECK(EmpSSLSocketManager::get_ssl_client() == nullptr);
  CHECK(EmpSSLSocketManager::get_ssl_server() != nullptr);
  EmpSSLSocketManager::destroy_ssl_server();
  CHECK(EmpSSLSocketManager::get_ssl_server() == nullptr);
  //! [EmpSSLSocketManagerDestroySSL]
}

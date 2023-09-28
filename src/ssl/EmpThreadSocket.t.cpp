#include "../doctest.h"
#include "EmpThreadSocket.hpp"
#include "TLSSocket.hpp"
#define SOCKET_SETUP
#include "TestUtil.hpp"
#include <thread>

// Just for testing across multiple types.
template <typename T> struct EmpThreadSocketTestClass { using type = T; };

//! [EmpThreadSocketSetSSL]
TEST_CASE_TEMPLATE("set_ssl", socket_type,
                   EmpThreadSocketTestClass<EmpClientSocket>,
                   EmpThreadSocketTestClass<EmpServerSocket>) {

  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  REQUIRE(ssl);

  using SocketType = typename socket_type::type;

  CHECK(SocketType::get_socket() == nullptr);
  SocketType::set_ssl(ssl.get());
  CHECK(SocketType::get_socket() != nullptr);
  CHECK(SocketType::get_socket()->get_ssl() == ssl.get());

  //! [EmpThreadSocketDestroySSL]
  CHECK(SocketType::get_socket() != nullptr);
  SocketType::destroy_ssl();
  CHECK(SocketType::get_socket() == nullptr);
  //! [EmpThreadSocketDestroySSL]
}
//! [EmpThreadSocketSetSSL]

//! [EmpThreadSocketConstruct]
TEST_CASE_TEMPLATE("construct", socket_type,
                   EmpThreadSocketTestClass<EmpClientSocket>,
                   EmpThreadSocketTestClass<EmpServerSocket>) {

  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  REQUIRE(ssl);
  using SocketType = typename socket_type::type;

  SocketType::set_ssl(ssl.get());

  SUBCASE("Just one") {
    SocketType sock("", 0, true); // The arguments here don't matter.
    CHECK(sock.get_socket()->get_ssl() == ssl.get());
    CHECK(sock.get_tag() == 0);
  }

  SUBCASE("Many") {
    for (unsigned i = 0; i < 100; i++) {
      SocketType sock("", 0, true); // The arguments here don't matter.
      CHECK(sock.get_socket()->get_ssl() == ssl.get());
      CHECK(sock.get_tag() == i);
    }
  }

  SocketType::destroy_ssl();
}
//! [EmpThreadSocketConstruct]

// This test isn't templated because it isn't needed.
TEST_CASE("send_recv") {
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);
  std::unique_ptr<TLSSocket> server, client;
  // Setup the connections.
  REQUIRE(setup_sockets(context, server, client));

  // Now we'll practice sending from the client to the server.
  // We'll do this using an existing connection from a ThreadSafeSSL object.
  EmpSSLSocketManager::create_ssl_server(server->get_ssl_object());
  EmpSSLSocketManager::create_ssl_client(client->get_ssl_object());

  // Make some data to send. This is fixed data, but there's no reason for that.
  std::array<uint8_t, 100> data;
  std::iota(data.begin(), data.end(), 0);

  EmpClientSocket client_socket("", 0,
                                true); // The arguments here don't matter.
  EmpServerSocket server_socket("", 0,
                                true); // The arguments here don't matter.

  auto client_code = [&]() {
    //! [EmpThreadSocketSendDataInternal]
    client_socket.send_data_internal(data.data(), data.size());
    client_socket.flush();
    //! [EmpThreadSocketSendDataInternal]

    //! [EmpThreadSocketRecvDataInternal]
    std::array<uint8_t, 100> in;
    client_socket.recv_data_internal(in.data(), in.size());
    CHECK(in == data);
    //! [EmpThreadSocketRecvDataInternal]
  };

  auto server_code = [&]() {
    std::array<uint8_t, 100> in;
    server_socket.recv_data_internal(in.data(), in.size());
    CHECK(in == data);
    server_socket.send_data_internal(in.data(), in.size());
    server_socket.flush();
  };

  std::thread server_thread(server_code);
  client_code();
  server_thread.join();

  // Have to destroy these at the end.
  EmpSSLSocketManager::destroy_ssl_server();
  EmpSSLSocketManager::destroy_ssl_client();
}

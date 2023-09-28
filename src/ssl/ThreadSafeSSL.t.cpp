#include "../doctest.h"
#include "TLSSocket.hpp"
#include "ThreadSafeSSL.hpp"
#include <numeric>
#define SOCKET_SETUP
#include "TestUtil.hpp"
#include <thread>

//! [ThreadSafeSSLConstructor]
TEST_CASE("constructor") {
  auto context = CreateContextWithTestCertificate(TLS_method());
  assert(context);
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  ThreadSafeSSL tssl(ssl.get());
  CHECK(tssl.get_ssl() == ssl.get());
}
//! [ThreadSafeSSLConstructor]

//! [ThreadSafeSSLRegisterNewSocket]
TEST_CASE("constructor") {
  auto context = CreateContextWithTestCertificate(TLS_method());
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  ThreadSafeSSL tssl(ssl.get());

  SUBCASE("linear") {
    CHECK(tssl.register_new_socket() == 0);
    CHECK(tssl.register_new_socket() == 1);
    CHECK(tssl.register_new_socket() == 2);
  }

  SUBCASE("loop") {
    for (unsigned i = 0; i < 100; i++) {
      CHECK(tssl.register_new_socket() == i);
    }
  }
}
//! [ThreadSafeSSLRegisterNewSocket]

//! [ThreadSafeSSLRegisteredIn]
TEST_CASE("registered_in") {
  // This function checks that a registered thread is actually in the initial
  // table.
  auto context = CreateContextWithTestCertificate(TLS_method());
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  std::unique_ptr<TLSSocket> server, client;
  REQUIRE(setup_sockets(context, server, client));
}
//! [ThreadSafeSSLRegisteredIn]

//! [ThreadSafeSSLSend]
TEST_CASE("send") {
  // This just checks that the sending code works as we'd expect.
  auto context = CreateContextWithTestCertificate(TLS_method());
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  std::unique_ptr<TLSSocket> server, client;
  REQUIRE(setup_sockets(context, server, client));

  // We'll use the server as the TSSL object.
  ThreadSafeSSL tssl(server->get_ssl_object());

  SUBCASE("random data, first time") {

    const auto tag = tssl.register_new_socket();
    std::array<uint8_t, 20> data;
    for (unsigned i = 0; i < data.size(); i++) {
      data[i] = static_cast<uint8_t>(rand());
    }

    auto send_code = [&]() { tssl.send(tag, data.data(), data.size()); };
    CHECK(!tssl.is_registered_out(tag));
    std::thread server_code(send_code);
    // The message is split into two portions: the header first, then the
    // message itself.
    struct Packed {
      unsigned header : 8;
      size_t size : 56;
    };

    Packed header;
    const auto nr_bytes =
        SSL_read(client->get_ssl_object(), &header, sizeof(header));
    CHECK(nr_bytes == sizeof(header));
    CHECK((unsigned)header.header == tag);
    CHECK((size_t)header.size == data.size());

    // Now we expect the message to be of size 20 * sizeof(uint8_t).
    uint8_t arr[data.size()];
    const auto nr_bytes_mes =
        SSL_read(client->get_ssl_object(), arr, sizeof(arr));
    REQUIRE(nr_bytes_mes == sizeof(arr));
    CHECK(memcmp(arr, data.data(), data.size()) == 0);

    // Now to get the server to terminate we need to write a tag back.
    // We'll just use 0.
    const uint8_t temp_tag = 0;
    CHECK(!tssl.is_registered_in(temp_tag));
    const auto written =
        SSL_write(client->get_ssl_object(), &temp_tag, sizeof(uint8_t));
    REQUIRE(written == sizeof(uint8_t));
    // We want to make sure the socket actually terminates.
    server_code.join();

    // Check that the tags are actually in the table.
    //! [ThreadSafeSSLRegisteredInOut]
    CHECK(tssl.is_registered_in(temp_tag));
    CHECK(tssl.is_registered_out(tag));
    //! [ThreadSafeSSLRegisteredInOut]
  }
}
//! [ThreadSafeSSLSend]

//! [ThreadSafeSSLMultiSend]
TEST_CASE("multi_send") {
  // This test case checks that both send and recv work together.
  // We do this by first establishing a set of connections between two tssl
  // objects and then checking that the reads work as expected.
  auto context = CreateContextWithTestCertificate(TLS_method());
  std::unique_ptr<TLSSocket> server, client;
  REQUIRE(setup_sockets(context, server, client));

  ThreadSafeSSL client_tssl(client->get_ssl_object());
  ThreadSafeSSL server_tssl(server->get_ssl_object());

  // Check that establishing the connection works.
  auto server_code = [&]() {
    for (unsigned i = 0; i < 10; i++) {
      // This counts from 0, so it's essentially `i`.
      server_tssl.register_new_socket();
      // Here we are going for a 1:1 mapping. This is just for ease of testing.
      CHECK(!server_tssl.is_registered_out(i));
      CHECK(!server_tssl.is_registered_in(i));
      server_tssl.send(i, &i, sizeof(i));
      CHECK(server_tssl.is_registered_out(i));
      CHECK(server_tssl.is_registered_in(i));
    }
  };

  std::thread server_establish(server_code);

  unsigned tmp_storage;
  for (unsigned i = 0; i < 10; i++) {
    client_tssl.register_new_socket();
    // Here we are going for a 1:1 mapping. This is just for ease of testing.
    CHECK(!client_tssl.is_registered_out(i));
    CHECK(!client_tssl.is_registered_in(i));
    client_tssl.recv(i, &tmp_storage, sizeof(tmp_storage));
    CHECK(tmp_storage == i);
    CHECK(client_tssl.is_registered_out(i));
    CHECK(client_tssl.is_registered_in(i));
  }

  server_establish.join();

  // Now we are going to send `i`, but in reverse. This is entirely to check
  // that the buffering works properly.
  SUBCASE("Sequential") {
    auto server_send_backwards = [&]() {
      for (int i = 9; i >= 0; i--) {
        unsigned as_unsigned = static_cast<unsigned>(i);
        server_tssl.send(as_unsigned, &as_unsigned, sizeof(as_unsigned));
      }
    };

    std::thread server_backwards_thread(server_send_backwards);
    for (unsigned i = 0; i < 10; i++) {
      client_tssl.recv(i, &tmp_storage, sizeof(tmp_storage));
      CHECK(tmp_storage == i);
    }

    server_backwards_thread.join();
  }

  SUBCASE("small_threaded") {
    // Now we'll do it from many threads at once, to many threads at once.
    // This is primarily to check that the buffering etc is actually thread
    // safe.
    std::array<std::thread, 10> client_threads;
    std::array<std::thread, 10> server_threads;

    auto client_send_code = [&](const unsigned i) {
      unsigned t_tmp_storage;
      client_tssl.recv(i, &t_tmp_storage, sizeof(t_tmp_storage));
      CHECK(t_tmp_storage == i);
    };

    auto server_send_code = [&](const unsigned i) {
      server_tssl.send(i, &i, sizeof(i));
    };

    for (unsigned i = 0; i < 10; i++) {
      client_threads[i] = std::thread(client_send_code, i);
      server_threads[i] = std::thread(server_send_code, 9 - i);
    }

    // N.B these joins are in separate threads to make sure that
    // the data from server thread has been sent before we require
    // any client threads to stop.
    for (unsigned i = 0; i < 10; i++) {
      server_threads[i].join();
    }

    for (unsigned i = 0; i < 10; i++) {
      client_threads[i].join();
    }
  }

  SUBCASE("large_threaded") {
    // Now we'll do it from many threads at once, to many threads at once, but
    // with lots of data. This is primarily to check whether we actually
    // can handle large batches of data.
    std::array<std::thread, 10> client_threads;
    std::array<std::thread, 10> server_threads;

    using BufType = std::array<char, 2 * SSL3_RT_MAX_PLAIN_LENGTH>;

    auto client_send_code = [&](const unsigned i) {
      BufType data;
      std::iota(data.begin(), data.end(), i);
      BufType in;
      client_tssl.recv(i, in.data(), sizeof(in));
      CHECK(in == data);
    };

    auto server_send_code = [&](const unsigned i) {
      BufType data;
      std::iota(data.begin(), data.end(), i);
      server_tssl.send(i, data.data(), sizeof(data));
    };

    for (unsigned i = 0; i < 10; i++) {
      client_threads[i] = std::thread(client_send_code, i);
      server_threads[i] = std::thread(server_send_code, 9 - i);
    }

    // N.B these joins are in separate threads to make sure that
    // the data from server thread has been sent before we require
    // any client threads to stop.
    for (unsigned i = 0; i < 10; i++) {
      server_threads[i].join();
    }

    for (unsigned i = 0; i < 10; i++) {
      client_threads[i].join();
    }
  }
}
//! [ThreadSafeSSLMultiSend]

//! [ThreadSafeSSLMismatchedSizeSends]
TEST_CASE("mismatched_size_send") {
  // This test case is to make sure that if one thread sends more data than is
  // expected to the receiver that everything still works.

  auto context = CreateContextWithTestCertificate(TLS_method());
  std::unique_ptr<TLSSocket> server, client;
  REQUIRE(setup_sockets(context, server, client));

  ThreadSafeSSL client_tssl(client->get_ssl_object());
  ThreadSafeSSL server_tssl(server->get_ssl_object());

  // We're going to do everything over tag 0. This means that the threads that
  // are used for communicating both have a tag of 0. This is just for ease of
  // testing: the behaviour we're simulating doesn't really require a particular
  // thread to be used.
  constexpr unsigned tag = 0;

  auto server_code = [&]() {
    // Just register a single new socket.
    server_tssl.register_new_socket();
    CHECK(!server_tssl.is_registered_out(tag));
    CHECK(!server_tssl.is_registered_in(tag));
    server_tssl.send(tag, &tag, sizeof(tag));
    CHECK(server_tssl.is_registered_out(tag));
    CHECK(server_tssl.is_registered_in(tag));
  };

  std::thread server_establish(server_code);

  // Now we'll do the same setup for the client.

  unsigned tmp_storage;
  client_tssl.register_new_socket();
  CHECK(!client_tssl.is_registered_out(tag));
  CHECK(!client_tssl.is_registered_in(tag));
  client_tssl.recv(tag, &tmp_storage, sizeof(tmp_storage));
  CHECK(tmp_storage == tag);
  CHECK(client_tssl.is_registered_out(tag));
  CHECK(client_tssl.is_registered_in(tag));

  server_establish.join();

  // Now we want to do the actual testing: sending mismatched data over.
  SUBCASE("small mismatch") {
    constexpr std::array<unsigned, 2> test_arr{1, 2};
    auto server_send = [&]() {
      server_tssl.send(tag, test_arr.data(),
                       test_arr.size() * sizeof(unsigned));
    };

    std::thread server_send_thread(server_send);
    unsigned recv{};
    for (unsigned i = 0; i < test_arr.size(); i++) {
      client_tssl.recv(tag, &recv, sizeof(unsigned));
      CHECK(recv == test_arr[i]);
    }

    server_send_thread.join();
  }

  SUBCASE("large mismatch") {
    std::vector<unsigned> vals(10000);
    for (auto &val : vals) {
      val = static_cast<unsigned>(rand());
    }

    auto server_send = [&]() {
      server_tssl.send(tag, vals.data(),
                       static_cast<unsigned>(vals.size() * sizeof(unsigned)));
    };

    std::thread server_send_thread(server_send);
    unsigned recv{};
    for (unsigned i = 0; i < vals.size(); i++) {
      client_tssl.recv(tag, &recv, sizeof(unsigned));
      CHECK(recv == vals[i]);
    }

    server_send_thread.join();
  }
}

//! [ThreadSafeSSLMismatchedSizeSends]

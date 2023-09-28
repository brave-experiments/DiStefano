#include "../doctest.h"
#include "TLSSocket.hpp"

#include "TestUtil.hpp"
#include "crypto/internal.h"
#include "openssl/bio.h"
#include "openssl/mem.h"
#include "openssl/ssl.h"
#include "ssl/internal.h"
#include <future>
#include <thread>

//! [TLSSocketConstructorTests]
TEST_CASE("Constructing a TLSSocket works") {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  TLSSocket ts(*ctx);
}
//! [TLSSocketConstructorTests]

//! [TLSSocketGetSSLErrorTests]
TEST_CASE("Getting the ssl error works") {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  TLSSocket ts(*ctx);

  SUBCASE("Passing in a positive integer should return no error") {
    // 5 is random: you can make this any positive integer.
    CHECK(ts.get_ssl_error(5) == SSL_ERROR_NONE);
  }

  SUBCASE("Passing in 0 should return SSL_ERROR_SYSCALL") {
    // This only happens because the TLS connection isn't initialised yet
    CHECK(ts.get_ssl_error(0) == SSL_ERROR_SYSCALL);
  }

  // The rest of the returns are context dependent.
}
//! [TLSSocketGetSSLErrorTests]

//! [TLSSocketSettingCertificateWorks]
TEST_CASE("TLSSocket set_ssl_certificate Tests") {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  TLSSocket ts(*ctx);

  SUBCASE("Calling set_ssl_certificate fails on a null pointer") {
    CHECK(!ts.set_ssl_certificate(nullptr));
  }

  SUBCASE("Calling set_ssl_certificate on a valid certificate works") {
    auto cert = GetTestCertificate();
    CHECK(ts.set_ssl_certificate(cert.get()));
  }
}
//! [TLSSocketSettingCertificateWorks]

//! [TLSSocketDoHandshakeTests]
TEST_CASE("TLSSocket do_handshake Tests") {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  TLSSocket ts(*ctx);

  SUBCASE("Calling do_handshake on a client fails") {
    TLSSocket cts(*ctx, false);
    CHECK(cts.do_handshake() == SSL_ERROR_WANT_CONNECT);
  }

  SUBCASE("Calling do_handshake without listen() fails") {
    TLSSocket cts(*ctx);
    CHECK(cts.do_handshake() == SSL_ERROR_WANT_ACCEPT);
  }
}
//! [TLSSocketDoHandshakeTests]

//! [TLSSocketWritePreconditionTests]
TEST_CASE("TLSSocket write preconditions tests") {
  // This test case is just meant to check that the pre-conditions
  // are met.
  // We'll test the rest later on.
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  TLSSocket ts(*ctx);

  SUBCASE("Passing in too much data fails") {
    bssl::Array<uint8_t> arr;
    arr.Init(SSL3_RT_MAX_PLAIN_LENGTH + 1);
    CHECK(!ts.write(arr.data(), arr.size()));
  }

  SUBCASE("Asking to write no data fails") {
    bssl::Array<uint8_t> arr;
    arr.Init(SSL3_RT_MAX_PLAIN_LENGTH + 1);
    CHECK(!ts.write(arr.data(), 0));
  }
}
//! [TLSSocketWritePreconditionTests]

// Now we need to be able to run the server in its own thread for actual
// communications. Both doctest and SSL_ctx's are thread safe, so this works
// safely.
static void server_handshake_operate(std::promise<bool> &&res,
                                     TLSSocket *server) {
  if (!server) {
    res.set_value(false);
    return;
  }

  if (!server->accept()) {
    res.set_value(false);
    return;
  }

  // 1 is the success condition.
  if (server->do_handshake() != 1) {
    res.set_value(false);
    return;
  }

  res.set_value(true);
  return;
}

//! [TLSSocketAcceptTests]
TEST_CASE("TLSSocket accept tests") {
  // This test case is just to make sure that calling accept() actually
  // transfers ownership.
  auto ctx = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(ctx);
  TLSSocket server(*ctx), client(*ctx, false);
  std::string out;
  uint16_t port;
  SUBCASE("Connection setup works") {
    REQUIRE(!server.get_ssl_object()->rbio);
    REQUIRE(!server.get_ssl_object()->wbio);
    SUBCASE("IPV4 connection setup works") {
      REQUIRE(server.set_family(AF_INET));
      REQUIRE(server.set_addr("127.0.0.1"));
      REQUIRE(server.bind());
      REQUIRE(server.listen(1));
      REQUIRE(server.get_hostname(out));
      const auto colon = out.find(":");
      REQUIRE(colon != std::string::npos);
      const auto addr = out.substr(0, colon);
      REQUIRE(addr == "127.0.0.1");
      REQUIRE(server.get_portnumber(&port));
      // Start the thread
      std::promise<bool> prom;
      auto res = prom.get_future();
      std::thread t(server_handshake_operate, std::move(prom), &server);
      REQUIRE(client.set_ip_v4());
      REQUIRE(client.connect_to("127.0.0.1", port));
      t.join();
      CHECK(res.get());
      // Most importantly: we care that the SSL object has a non-null BIO.
      CHECK(server.get_ssl_object()->rbio);
      CHECK(server.get_ssl_object()->wbio);
    }

    SUBCASE("IPV6 connection setup works") {
      REQUIRE(server.set_family(AF_INET6));
      REQUIRE(server.set_addr("::1"));
      REQUIRE(server.bind());
      REQUIRE(server.listen(1));
      REQUIRE(server.get_hostname(out));
      // `out` is now formatted as [%s]:%d. We want the %s.
      // We know that [ is at position 0, so all we need to do is find the ]
      const auto right_bracket = out.find("]");
      REQUIRE(right_bracket != std::string::npos);
      // Warning: C++ requires you to specify the _size_ of the string
      // as the second argument here.
      // This is right_bracket - 1, because we're starting from 1.
      const auto addr = out.substr(1, right_bracket - 1);
      REQUIRE(addr == "::1");
      REQUIRE(server.get_portnumber(&port));

      // Start the server's thread
      std::promise<bool> prom;
      auto res = prom.get_future();
      std::thread t(server_handshake_operate, std::move(prom), &server);
      REQUIRE(client.set_ip_v6());
      REQUIRE(client.connect_to("::1", port));
      t.join();
      CHECK(res.get());
    }
    // Most importantly: we care that the SSL object has a non-null BIO.
    CHECK(server.get_ssl_object()->rbio);
    CHECK(server.get_ssl_object()->wbio);
  }
}
//! [TLSSocketAcceptTests]

static void server_read_write_operate(std::promise<std::string> &&res,
                                      TLSSocket *server) {
  // This function just reads a string from the socket and then writes the same
  // string.
  if (!server) {
    res.set_value("");
    return;
  }

  char value[80];
  auto return_code = server->read(value, sizeof(value));
  if (return_code <= 0) {
    res.set_value("");
    return;
  }

  // Write it out again
  if (!server->write(value, sizeof(value))) {
    res.set_value("");
    return;
  }

  res.set_value(std::string(value));
  return;
}

//! [TLSSocketConnectToTests]
TEST_CASE("TLSSocketConnectToTests") {
  // This test case is meant to make sure that it's possible to use
  // TLSSockets to send and receive data.
  auto ctx = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(ctx);
  TLSSocket server(*ctx), client(*ctx, false);

  // We won't duplicate any of the functionality tests here: those are tested in
  // StatefulSocket's tests.
  //  static const char TestMessage[] = "TestMessage";
  std::string out;
  uint16_t port;
  std::promise<bool> prom;
  SUBCASE("Connection setup works") {
    SUBCASE("IPV4 connection setup works") {
      REQUIRE(server.set_family(AF_INET));
      REQUIRE(server.set_addr("127.0.0.1"));
      REQUIRE(server.bind());
      REQUIRE(server.listen(1));
      REQUIRE(server.get_hostname(out));
      const auto colon = out.find(":");
      REQUIRE(colon != std::string::npos);
      const auto addr = out.substr(0, colon);
      REQUIRE(addr == "127.0.0.1");
      REQUIRE(server.get_portnumber(&port));
      // Start the thread
      auto res = prom.get_future();
      std::thread t(server_handshake_operate, std::move(prom), &server);
      REQUIRE(client.set_ip_v4());
      REQUIRE(client.connect_to("127.0.0.1", port));
      t.join();
      CHECK(res.get());
    }

    SUBCASE("IPV6 connection setup works") {
      REQUIRE(server.set_family(AF_INET6));
      REQUIRE(server.set_addr("::1"));
      REQUIRE(server.bind());
      REQUIRE(server.listen(1));
      REQUIRE(server.get_hostname(out));
      // `out` is now formatted as [%s]:%d. We want the %s.
      // We know that [ is at position 0, so all we need to do is find the ]
      const auto right_bracket = out.find("]");
      REQUIRE(right_bracket != std::string::npos);
      // Warning: C++ requires you to specify the _size_ of the string
      // as the second argument here.
      // This is right_bracket - 1, because we're starting from 1.
      const auto addr = out.substr(1, right_bracket - 1);
      REQUIRE(addr == "::1");
      REQUIRE(server.get_portnumber(&port));

      // Start the server's thread
      auto res = prom.get_future();
      std::thread t(server_handshake_operate, std::move(prom), &server);
      REQUIRE(client.set_ip_v6());
      REQUIRE(client.connect_to("::1", port));
      t.join();
      CHECK(res.get());
    }
  }

  //! [TLSSocketReadWriteTests]
  // Now we've done the handshake in either case, let's also try and do some
  // reading and writing.
  static const char TestMessage[] = "TestMessage";
  std::promise<std::string> str_prom;
  auto fut = str_prom.get_future();
  std::thread t(server_read_write_operate, std::move(str_prom), &server);
  REQUIRE(client.write(TestMessage, sizeof(TestMessage)));
  char response[sizeof(TestMessage)];
  REQUIRE(client.read(response, sizeof(response)) == sizeof(TestMessage));
  t.join();

  const auto out_string = fut.get();
  CHECK(out_string == TestMessage);
  CHECK(out_string == response);
  //! [TLSSocketReadWriteTests]
}
//! [TLSSocketConnectToTests]

// N.B this function is used as a function pointer stub.
static bool commit_to_key_shares_test(SSL *, bssl::SSL_HANDSHAKE *) {
  return true;
}

static bool send_keyshare_test(SSL *, uint16_t, CBS &) { return true; }

//! [TLSSocketIsSSLValidTests]
TEST_CASE("TLSSocket is_ssl_valid tests") {
  // This function is really straightforward to test:
  // the main way to force this to fail is to pass in a null pointer to the
  // constructor.
  auto ctx = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(ctx);
  SUBCASE("An invalid socket is created without a valid context") {
    TLSSocket fail_cts(nullptr);
    CHECK(!fail_cts.is_ssl_valid());
  }

  SUBCASE("A valid socket is created with a valid context (reference "
          "constructor)") {
    TLSSocket cts(*ctx);
    CHECK(cts.is_ssl_valid());
  }

  SUBCASE(
      "A valid socket is created with a valid context (pointer constructor)") {
    TLSSocket cts(ctx.get());
    CHECK(cts.is_ssl_valid());
  }
}
//! [TLSSocketIsSSLValidTests]

//! [TLSSocketGetSSLObjectTests]
TEST_CASE("TLSSocket get_ssl_object_tests") {
  // The main test case here is that the call works and retrieves a valid
  // context.
  auto ctx = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(ctx);
  TLSSocket ts(*ctx), clts(*ctx, false);

  REQUIRE(ts.is_ssl_valid());
  REQUIRE(clts.is_ssl_valid());

  SUBCASE("A null pointer is not returned") {
    // This only happens because the socket must be valid due to the above
    // checks.
    CHECK(ts.get_ssl_object() != nullptr);
    CHECK(clts.get_ssl_object() != nullptr);
  }

  SUBCASE("The same pointer is returned") {
    const auto ssl_object = ts.get_ssl_object();
    REQUIRE(ssl_object != nullptr);
    CHECK(ssl_object == ts.get_ssl_object());
    // This is the same if you repeat it arbitrarily many times
    constexpr auto repeats = 100;
    for (unsigned i = 0; i < repeats; i++) {
      CHECK(ssl_object == ts.get_ssl_object());
    }
  }
}
//! [TLSSocketGetSSLObjectTests]

//! [TLSSocketGetHandshakeCallbackTests]
TEST_CASE("TLSSocket get_handshake_callback tests") {
  // This test case is meant to make sure that it's possible to use
  // TLSSockets as a wrapper around retrieving the handshake callback.
  // NOTE: this technically exposes the inner workings of TLSSocket.
  // This is OK, but it shouldn't be relied upon.
  auto ctx = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(ctx);
  TLSSocket server(*ctx), client(*ctx, false);

  SUBCASE("The handshake callback should be null by default") {
    const auto is_server_hsc_null = server.get_handshake_callback() == nullptr;
    const auto is_client_hsc_null = client.get_handshake_callback() == nullptr;
    CHECK(is_server_hsc_null);
    CHECK(is_client_hsc_null);
  }

  SUBCASE("Setting the callback manually is reflected") {
    auto ssl_object = client.get_ssl_object();
    REQUIRE(ssl_object != nullptr);
    // We'll set the callback manually
    REQUIRE(
        SSL::set_commit_to_key_shares(ssl_object, &commit_to_key_shares_test));
    // And now the returned value should be the same as the function passed in.
    const auto is_right_ptr =
        client.get_handshake_callback() == &commit_to_key_shares_test;
    CHECK(is_right_ptr);
  }
}
//! [TLSSocketGetHandshakeCallbackTests]

//! [TLSSocketSetHandshakeCallbackTests]
TEST_CASE("TLSSocket set_handshake_callback tests") {
  // This test case is meant to make sure that it's possible to use
  // TLSSockets as a wrapper around setting the handshake callback.
  auto ctx = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(ctx);
  TLSSocket server(*ctx), client(*ctx, false);

  //! [TLSSocketGetHandshakeFallbackNullNull]
  SUBCASE("Retrieving on a null object retrieves null") {
    TLSSocket fails(nullptr);
    REQUIRE(!fails.is_ssl_valid());
    const auto is_null = fails.get_handshake_callback() == nullptr;
    CHECK(is_null);
  }
  //! [TLSSocketGetHandshakeFallbackNullNull]

  //! [TLSSocketCannotSetServerCallback]
  SUBCASE("Can't set the callback on a server") {
    // This is just because it's a server connection: if it were
    // a client we'd expect this to work.
    CHECK(!server.set_handshake_callback(&commit_to_key_shares_test));
  }
  //! [TLSSocketCannotSetServerCallback]

  //! [TLSSocketSetHandshakeCallback]
  SUBCASE("Calling set_handshake_callback sets something") {
    const auto is_handshake_callback_null =
        client.get_handshake_callback() == nullptr;
    REQUIRE(is_handshake_callback_null);
    client.set_handshake_callback(&commit_to_key_shares_test);
    const auto is_handshake_callback_non_null =
        client.get_handshake_callback() != nullptr;
    CHECK(is_handshake_callback_non_null);
  }

  SUBCASE("Calling set_handshake_callback sets the right thing") {
    const auto is_handshake_callback_null =
        client.get_handshake_callback() == nullptr;
    REQUIRE(is_handshake_callback_null);
    client.set_handshake_callback(&commit_to_key_shares_test);
    const auto is_handshake_callback_correct =
        client.get_handshake_callback() == &commit_to_key_shares_test;
    CHECK(is_handshake_callback_correct);
  }
  //! [TLSSocketSetHandshakeCallback]
}
//! [TLSSocketSetHandshakeCallbackTests]

//! [TLSSocketGetKeyshareCallbackTests]
TEST_CASE("TLSSocket get_keyshare_callback tests") {
  // This test case is meant to make sure that it's possible to use
  // TLSSockets as a wrapper around retrieving the handshake callback.
  // NOTE: this technically exposes the inner workings of TLSSocket.
  // This is OK, but it shouldn't be relied upon.
  auto ctx = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(ctx);
  TLSSocket server(*ctx), client(*ctx, false);

  SUBCASE("The handshake callback should be null by default") {
    const auto is_server_hsc_null = server.get_keyshare_callback() == nullptr;
    const auto is_client_hsc_null = client.get_keyshare_callback() == nullptr;
    CHECK(is_server_hsc_null);
    CHECK(is_client_hsc_null);
  }

  SUBCASE("Setting the callback manually is reflected") {
    auto ssl_object = client.get_ssl_object();
    REQUIRE(ssl_object != nullptr);
    // We'll set the callback manually
    REQUIRE(SSL::set_send_key_shares(ssl_object, &send_keyshare_test));
    // And now the returned value should be the same as the function passed in.
    const auto is_right_ptr =
        client.get_keyshare_callback() == &send_keyshare_test;
    CHECK(is_right_ptr);
  }
}
//! [TLSSocketGetKeyshareCallbackTests]

//! [TLSSocketSetKeyshareCallbackTests]
TEST_CASE("TLSSocket set_handshake_callback tests") {
  // This test case is meant to make sure that it's possible to use
  // TLSSockets as a wrapper around setting the handshake callback.
  auto ctx = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(ctx);
  TLSSocket server(*ctx), client(*ctx, false);

  //! [TLSSocketGetKeyshareCallbackNullNull]
  SUBCASE("Retrieving on a null object retrieves null") {
    TLSSocket fails(nullptr);
    REQUIRE(!fails.is_ssl_valid());
    const auto is_null = fails.get_keyshare_callback() == nullptr;
    CHECK(is_null);
  }
  //! [TLSSocketGetKeyshareCallbackNullNull]

  SUBCASE("Can't set the callback on a server") {
    // This is just because it's a server connection: if it were
    // a client we'd expect this to work.
    CHECK(!server.set_keyshare_callback(&send_keyshare_test));
  }

  //! [TLSSocketSetKeyshareCallback]
  SUBCASE("Calling set_keyshare_callback sets something") {
    const auto is_keyshare_callback_null =
        client.get_keyshare_callback() == nullptr;
    REQUIRE(is_keyshare_callback_null);
    client.set_keyshare_callback(&send_keyshare_test);
    const auto is_keyshare_callback_non_null =
        client.get_keyshare_callback() != nullptr;
    CHECK(is_keyshare_callback_non_null);
  }

  SUBCASE("Calling set_keyshare_callback sets the right thing") {
    const auto is_keyshare_callback_null =
        client.get_keyshare_callback() == nullptr;
    REQUIRE(is_keyshare_callback_null);
    client.set_keyshare_callback(&send_keyshare_test);
    const auto is_keyshare_callback_correct =
        client.get_keyshare_callback() == &send_keyshare_test;
    CHECK(is_keyshare_callback_correct);
  }
  //! [TLSSocketSetKeyshareCallback]
}
//! [TLSSocketSetKeyshareCallbackTests]

// WARNING: this is *just* for testing.
// In particular, we're setting a global variable here
// to check that the function actually gets called during a TLS handshake.
// In general this is _bad_ practice.
unsigned commit_to_key_shares_was_called_how_many_times = 0;
unsigned send_keyshare_was_called_how_many_times = 0;

static bool commit_to_key_shares_was_called(SSL *, bssl::SSL_HANDSHAKE *) {
  commit_to_key_shares_was_called_how_many_times++;
  return true;
}

static bool send_key_was_called(SSL *, uint16_t, CBS &) {
  send_keyshare_was_called_how_many_times++;
  return true;
}

TEST_CASE("TLSSocket test if callback is called") {
  auto ctx = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(ctx);
  TLSSocket server(*ctx), client(*ctx, false);
  REQUIRE(server.is_ssl_valid());
  REQUIRE(client.is_ssl_valid());

  // This just makes sure that the callback is set.
  REQUIRE(client.set_handshake_callback(&commit_to_key_shares_was_called));
  // This _must_ be reset here. The reason why is because
  // doctest treats each test case as a tree: everything outside of the SUBCASE
  // is executed, and then one of the SUBCASEs is called. However, since
  // `how_many_times_called` is incremented each time
  // `commit_to_key_shared_was_called` is called, the subcases technically
  // overlap. Resetting this here is hence mandatory.
  commit_to_key_shares_was_called_how_many_times = 0;

  std::string out;
  uint16_t port;
  std::promise<bool> prom;

  SUBCASE("Callback is called") {
    SUBCASE("IPV4 connection") {
      REQUIRE(server.set_family(AF_INET));
      REQUIRE(server.set_addr("127.0.0.1"));
      REQUIRE(server.bind());
      REQUIRE(server.listen(1));
      REQUIRE(server.get_hostname(out));
      const auto colon = out.find(":");
      REQUIRE(colon != std::string::npos);
      const auto addr = out.substr(0, colon);
      REQUIRE(addr == "127.0.0.1");
      REQUIRE(server.get_portnumber(&port));

      // Start the thread
      auto res = prom.get_future();
      std::thread t(server_handshake_operate, std::move(prom), &server);
      REQUIRE(client.set_ip_v4());
      REQUIRE(client.connect_to("127.0.0.1", port));
      t.join();
      REQUIRE(res.get());
      CHECK(commit_to_key_shares_was_called_how_many_times == 1);
    }

    SUBCASE("IPV6 connection") {
      REQUIRE(server.set_family(AF_INET6));
      REQUIRE(server.set_addr("::1"));
      REQUIRE(server.bind());
      REQUIRE(server.listen(1));
      REQUIRE(server.get_hostname(out));
      // `out` is now formatted as [%s]:%d. We want the %s.
      // We know that [ is at position 0, so all we need to do is find the ]
      const auto right_bracket = out.find("]");
      REQUIRE(right_bracket != std::string::npos);
      // Warning: C++ requires you to specify the _size_ of the string
      // as the second argument here.
      // This is right_bracket - 1, because we're starting from 1.
      const auto addr = out.substr(1, right_bracket - 1);
      REQUIRE(addr == "::1");
      REQUIRE(server.get_portnumber(&port));

      // Start the server's thread
      auto res = prom.get_future();
      std::thread t(server_handshake_operate, std::move(prom), &server);
      REQUIRE(client.set_ip_v6());
      REQUIRE(client.connect_to("::1", port));
      t.join();
      REQUIRE(res.get());
      CHECK(commit_to_key_shares_was_called_how_many_times == 1);
    }
  }
}

TEST_CASE("TLSSocket test if keyshare callback is called") {
  auto ctx = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(ctx);
  TLSSocket server(*ctx), client(*ctx, false);
  REQUIRE(server.is_ssl_valid());
  REQUIRE(client.is_ssl_valid());

  // This just makes sure that the callback is set.
  REQUIRE(client.set_keyshare_callback(&send_key_was_called));
  // This _must_ be reset here. The reason why is because
  // doctest treats each test case as a tree: everything outside of the SUBCASE
  // is executed, and then one of the SUBCASEs is called. However, since
  // `how_many_times_called` is incremented each time
  // `commit_to_key_shared_was_called` is called, the subcases technically
  // overlap. Resetting this here is hence mandatory.
  send_keyshare_was_called_how_many_times = 0;

  std::string out;
  uint16_t port;
  std::promise<bool> prom;

  SUBCASE("Callback is called") {
    SUBCASE("IPV4 connection") {
      REQUIRE(server.set_family(AF_INET));
      REQUIRE(server.set_addr("127.0.0.1"));
      REQUIRE(server.bind());
      REQUIRE(server.listen(1));
      REQUIRE(server.get_hostname(out));
      const auto colon = out.find(":");
      REQUIRE(colon != std::string::npos);
      const auto addr = out.substr(0, colon);
      REQUIRE(addr == "127.0.0.1");
      REQUIRE(server.get_portnumber(&port));

      // Start the thread
      auto res = prom.get_future();
      std::thread t(server_handshake_operate, std::move(prom), &server);
      REQUIRE(client.set_ip_v4());
      REQUIRE(client.connect_to("127.0.0.1", port));
      t.join();
      REQUIRE(res.get());
      CHECK(send_keyshare_was_called_how_many_times == 1);
    }

    SUBCASE("IPV6 connection") {
      REQUIRE(server.set_family(AF_INET6));
      REQUIRE(server.set_addr("::1"));
      REQUIRE(server.bind());
      REQUIRE(server.listen(1));
      REQUIRE(server.get_hostname(out));
      // `out` is now formatted as [%s]:%d. We want the %s.
      // We know that [ is at position 0, so all we need to do is find the ]
      const auto right_bracket = out.find("]");
      REQUIRE(right_bracket != std::string::npos);
      // Warning: C++ requires you to specify the _size_ of the string
      // as the second argument here.
      // This is right_bracket - 1, because we're starting from 1.
      const auto addr = out.substr(1, right_bracket - 1);
      REQUIRE(addr == "::1");
      REQUIRE(server.get_portnumber(&port));

      // Start the server's thread
      auto res = prom.get_future();
      std::thread t(server_handshake_operate, std::move(prom), &server);
      REQUIRE(client.set_ip_v6());
      REQUIRE(client.connect_to("::1", port));
      t.join();
      REQUIRE(res.get());
      CHECK(send_keyshare_was_called_how_many_times == 1);
    }
  }
}

//! [TLSSocketSettingVerifierConnectionWorks]
TEST_CASE("Setting verifier connection works") {
  auto ctx = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(ctx);
  TLSSocket server(*ctx), client(*ctx, false);
  REQUIRE(server.is_ssl_valid());
  REQUIRE(client.is_ssl_valid());

  SUBCASE("Can't set the verifier connection on a server") {
    CHECK(!server.set_verifier_connection(nullptr));
    CHECK(!server.set_verifier_connection(client.get_ssl_object()));
  }

  SUBCASE("Passing in a null pointer works") {
    CHECK(client.set_verifier_connection(nullptr));
  }

  // NOTE: this is a clearbox text, as it relies on us knowing the layout of the
  // SSL object. This is primarily to make it easier to test the getter in the
  // next step.
  SUBCASE("Setting the verifier works") {
    CHECK(client.set_verifier_connection(server.get_ssl_object()));
    CHECK(client.get_ssl_object()->verifier == server.get_ssl_object());
  }
}
//! [TLSSocketSettingVerifierConnectionWorks]

//! [TLSSocketGettingVerifierConnectionWorks]
TEST_CASE("Getting verifier connection works") {
  auto ctx = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(ctx);
  TLSSocket server(*ctx), client(*ctx, false);
  REQUIRE(server.is_ssl_valid());
  REQUIRE(client.is_ssl_valid());

  SUBCASE("Getting the connection on a server returns a nullptr") {
    CHECK(server.get_verifier_connection() == nullptr);
  }

  SUBCASE("Default getter on client returns nullptr") {
    CHECK(client.get_verifier_connection() == nullptr);
  }

  SUBCASE("Getting the verifier after setting works") {
    REQUIRE(client.set_verifier_connection(server.get_ssl_object()));
    CHECK(client.get_verifier_connection() == server.get_ssl_object());
  }
}
//! [TLSSocketGettingVerifierConnectionWorks]

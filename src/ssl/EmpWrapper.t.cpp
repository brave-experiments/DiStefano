#include "EmpWrapper.hpp"
#include "TestUtil.hpp"

#include "../doctest.h"
#include "TLSSocket.hpp"
#include "openssl/base.h"
#include "openssl/rand.h"
#include "openssl/ssl.h"
#include "ssl/internal.h"
#include <emp-ot/emp-ot.h>

//! [EmpWrapperTestConstruct]
TEST_CASE("Test_Construct") {
  bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_method()));
  REQUIRE(context);
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  REQUIRE(ssl);
  //! [EmpWrapperIsValidSSLValidPtrTest]
  SUBCASE("Is_Valid_SSL_works_on_valid_ptr") {
    EmpWrapper<> e{ssl.get()};
    CHECK(e.is_valid_ssl());
  }
  //! [EmpWrapperIsValidSSLValidPtrTest]

  //! [EmpWrapperIsValidSSLNullPtrTest]
  SUBCASE("Is_Valid_SSL_fails_on_nullptr") {
    // Note the constructor still goes through.
    EmpWrapper<> e{nullptr};
    CHECK(!e.is_valid_ssl());
  }
  //! [EmpWrapperIsValidSSLNullPtrTest]
}
//! [EmpWrapperTestConstruct]

//! [EmpWrapperSendRecvTests]
TEST_CASE("TEST_SEND_RECV") {
  // Let's check if we can actually send and receive
  // data, but without wrapping first.
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);

  static constexpr auto message = "Hello";
  const auto size = strlen(message);

  TLSSocket sender{context.get()};
  uint16_t port;

  REQUIRE(sender.set_ip_v4());
  REQUIRE(sender.set_addr("127.0.0.1"));
  REQUIRE(sender.bind());
  REQUIRE(sender.listen(1));
  REQUIRE(sender.get_portnumber(&port));

  const auto sender_code = [&]() {
    REQUIRE(sender.accept());
    REQUIRE(sender.do_handshake() == 1);
    EmpWrapper<> send_wrapped(sender.get_ssl_object());
    send_wrapped.send_data_internal(message, size);
    send_wrapped.flush();
  };

  // Now we'll set up the receiver.
  TLSSocket receiver_socket{context.get(), false};
  REQUIRE(receiver_socket.is_ssl_valid());
  std::thread t(sender_code);
  REQUIRE(receiver_socket.set_ip_v4());
  REQUIRE(receiver_socket.connect_to("127.0.0.1", port));
  char recv_into[100];
  EmpWrapper<> recv_wrapped(receiver_socket.get_ssl_object());
  recv_wrapped.recv_data_internal(recv_into, size);
  CHECK(strncmp(recv_into, message, size) == 0);
  t.join();
}
//! [EmpWrapperSendRecvTests]

//! [EmpWrapperDoOTTests]
TEST_CASE("TEST_OT") {
  // This test case is all about being able to actually do oblivious transfer
  // using EMP using our sockets. It's a one-shot thing. Note that this test may
  // fail for one of three reasons:
  // 1. Our code is wrong.
  // 2. BoringSSL fails, or
  // 3. Emp fails.
  // Obviously these may be outside of your control: hopefully the crash logs
  // are useful in any case.
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);

  // Now we want to provide these to EMP.
  // We'll slightly mimic the set-up given in the emp-ot repo.
  constexpr static auto length = 128;
  emp::block b0[length], b1[length], r[length];
  bool c[length];

  // We'll generate the random data first.
  // NOTE: this key should only be fixed in tests!!!
  emp::PRG prg(emp::fix_key);
  prg.random_block(b0, length);
  prg.random_block(b1, length);
  emp::PRG prg2;
  prg2.random_bool(c, length);

  // This is the sender set-up. We'll use a TLSSocket to check that all works
  // over TLS.
  TLSSocket sender{context.get()};
  uint16_t port;

  REQUIRE(sender.set_ip_v4());
  REQUIRE(sender.set_addr("127.0.0.1"));
  REQUIRE(sender.bind());
  REQUIRE(sender.listen(1));
  REQUIRE(sender.get_portnumber(&port));

  // Now we're going to create a new thread for the server to use.
  // This is primarily to make it easier to test.
  const auto sender_code = [&]() {
    REQUIRE(sender.accept());
    REQUIRE(sender.do_handshake() == 1);
    // Now we'll wrap the object as an OT object.
    EmpWrapper<> sender_wrap(sender.get_ssl_object());
    // And now we'll make the Naor-Pinkas OT.
    OTNP<EmpWrapper<>> sender_ot(&sender_wrap);
    sender_ot.send(b0, b1, length);
  };

  // Now we'll set up the receiver.
  TLSSocket receiver_socket{context.get(), false};
  REQUIRE(receiver_socket.is_ssl_valid());
  std::thread t(sender_code);
  REQUIRE(receiver_socket.set_ip_v4());
  REQUIRE(receiver_socket.connect_to("127.0.0.1", port));

  // Now we'll wrap the receiver object's SSL object in an EmpWrapper.
  EmpWrapper<> receiver(receiver_socket.get_ssl_object());

  // And now we'll supply our wrapper to an OTNP use-case. This is a Naor-Pinkas
  // OT, which is a classic protocol

  emp::OTNP<EmpWrapper<>> receiver_ot(&receiver);

  // Now we'll do the OT. We'll run the server first and then the client.
  receiver_ot.recv(r, c, length);

  // Finally, we'll check that the received variant is what we asked for.
  for (auto i = 0; i < length; i++) {
    if (c[i]) {
      CHECK(emp::cmpBlock(&r[i], &b1[i], 1));
    } else {
      CHECK(emp::cmpBlock(&r[i], &b0[i], 1));
    }
  }
  // The thread needs to be explicitly tidied up.
  t.join();
}
//! [EmpWrapperDoOTTests]

//! [EmpWrapperDoCOTTests]
TEST_CASE("TEST_COT") {
  // This test case is all about being able to actually do correlated oblivious
  // transfer (FerretOT) using EMP using our sockets. It's a one-shot thing.
  // Note that this test may fail for one of three reasons:
  // 1. Our code is wrong.
  // 2. BoringSSL fails, or
  // 3. Emp fails.
  // Obviously these may be outside of your control: hopefully the crash logs
  // are useful in any case.
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);

  // Now we want to provide these to EMP.
  // We'll slightly mimic the set-up given in the emp-ot repo.
  constexpr static auto length = 128;
  emp::block b0[length], b1[length], r[length];
  bool c[length];

  // We'll generate the random data first.
  // NOTE: this key should only be fixed in tests!!!
  emp::PRG prg(emp::fix_key);
  prg.random_block(b0, length);
  prg.random_block(b1, length);
  emp::PRG prg2;
  prg2.random_bool(c, length);

  // This is the sender set-up. We'll use a TLSSocket to check that all works
  // over TLS.
  TLSSocket sender{context.get()};
  uint16_t port;

  REQUIRE(sender.set_ip_v4());
  REQUIRE(sender.set_addr("127.0.0.1"));
  REQUIRE(sender.bind());
  REQUIRE(sender.listen(1));
  REQUIRE(sender.get_portnumber(&port));

  // Now we're going to create a new thread for the server to use.
  // This is primarily to make it easier to test.
  const auto sender_code = [&]() {
    REQUIRE(sender.accept());
    REQUIRE(sender.do_handshake() == 1);
    // Now we'll wrap the object as an OT object.
    EmpWrapper<> sender_wrap(sender.get_ssl_object());
    // And now we'll make the Ferret OT. We'll use this node as "Alice" and
    // the top-most thread as "Bob", which corresponds to this thread being the
    // sender and the top thread being the receiver.
    // NOTE: one weird quirk is that the sender needs to be placed in an array
    // of pointers. No idea why.
    EmpWrapper<> *ios[1]{&sender_wrap};

    emp::FerretCOT<EmpWrapper<>> sender_ot(ALICE, 1, ios, true);
    sender_ot.send(b0, b1, length);
  };

  // Now we'll set up the receiver.
  TLSSocket receiver_socket{context.get(), false};
  REQUIRE(receiver_socket.is_ssl_valid());
  std::thread t(sender_code);
  REQUIRE(receiver_socket.set_ip_v4());
  REQUIRE(receiver_socket.connect_to("127.0.0.1", port));

  // Now we'll wrap the receiver object's SSL object in an EmpWrapper.
  EmpWrapper<> receiver(receiver_socket.get_ssl_object());

  // And now we'll make the Ferret OT. As above, this corresponds to "Bob".
  // Again: there's a weird quirk in that the sender needs to be placed in an
  // array of pointers.
  EmpWrapper<> *ios[1]{&receiver};
  emp::FerretCOT<EmpWrapper<>> receiver_ot(BOB, 1, ios, true);

  // Now we'll do the OT. We'll run the server first and then the client.
  receiver_ot.recv(r, c, length);

  // Finally, we'll check that the received variant is what we asked for.
  for (auto i = 0; i < length; i++) {
    if (c[i]) {
      CHECK(emp::cmpBlock(&r[i], &b1[i], 1));
    } else {
      CHECK(emp::cmpBlock(&r[i], &b0[i], 1));
    }
  }
  // The thread needs to be explicitly tidied up.
  t.join();
}
//! [EmpWrapperDoCOTTests]

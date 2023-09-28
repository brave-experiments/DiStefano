#include "../doctest.h"
#include "../ssl/Messaging.hpp"
#include "../ssl/TestUtil.hpp"

#include "Server.hpp"
#include <array>
#include <exception>
#include <future>
#include <iostream>

//! [ServerConstructorTests]
TEST_CASE("Building a server works") {
  SUBCASE("Building ipv4 works") {
    Server s(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1", false,
             1);
  }

  SUBCASE("Building ipv6 works") {
    Server s(CreateContextWithTestCertificate(TLS_method()), "::1", true, 1);
  }
}
//! [ServerConstructorTests]

//! [ServerCreateNewShare]
TEST_CASE("Creating a new share works") {
  Server server(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1",
                false, 1);

  // Make testing a little bit quicker.
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());
  // We'll try it for all curves.
  std::array<uint16_t, 4> curves{SSL_CURVE_SECP224R1, SSL_CURVE_SECP256R1,
                                 SSL_CURVE_SECP384R1, SSL_CURVE_SECP521R1};
  SUBCASE("Making a share with a single key works") {
    // NOTE: this test doesn't check that the created share is _correct_.
    for (auto curve : curves) {
      bssl::UniquePtr<EC_GROUP> group(
          EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve)));
      REQUIRE(group);
      auto other_party = bssl::SSLKeyShare::Create(curve);
      REQUIRE(other_party);
      bssl::Array<uint8_t> other_key_bytes;
      REQUIRE(Util::generate_public_key(*other_party, other_key_bytes));
      // Now we'll ask the server to generate additive key shares.
      const auto created_properly = server.create_new_share(other_key_bytes);
      CHECK(created_properly);
    }
  }
}
//! [ServerCreateNewShare]

//! [ServerGetCurveIDTests]
TEST_CASE("Getting the CurveID works") {
  Server server(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1",
                false, 1);

  constexpr std::array<uint16_t, 2> zero{0, 0};
  SUBCASE("In the beginning it's 0,0") {
    CHECK(server.get_curve_ids() == zero);
  }

  // We'll try it for all curves.
  std::array<uint16_t, 4> curves{SSL_CURVE_SECP224R1, SSL_CURVE_SECP256R1,
                                 SSL_CURVE_SECP384R1, SSL_CURVE_SECP521R1};

  SUBCASE("After making a new share the first co-ordinate is the same as the "
          "curve ID") {

    // NOTE: this test doesn't check that the created share is _correct_.
    for (auto curve : curves) {
      bssl::UniquePtr<EC_GROUP> group(
          EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve)));
      REQUIRE(group);
      auto other_party = bssl::SSLKeyShare::Create(curve);
      REQUIRE(other_party);
      bssl::Array<uint8_t> other_key_bytes;
      REQUIRE(Util::generate_public_key(*other_party, other_key_bytes));
      // Now we'll ask the server to generate additive key shares.
      REQUIRE(server.create_new_share(other_key_bytes));

      // Now we'll retrieve the curve ID
      auto curve_ids = server.get_curve_ids();
      CHECK(curve_ids[0] == curve);
      // We don't expect this test to create 2 key shares.
      CHECK(curve_ids[1] == 0);
    }
  }
}
//! [ServerGetCurveID]

//! [ServerCreatingMultipleSharesWorks]
TEST_CASE("We can make multiple shares") {
  Server server(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1",
                false, 1);

  constexpr std::array<uint16_t, 2> zero{0, 0};
  SUBCASE("In the beginning it's 0,0") {
    CHECK(server.get_curve_ids() == zero);
  }

  SUBCASE("Otherwise it's as expected") {

    // We'll try it for all curves.
    constexpr std::array<uint16_t, 4> curves{
        SSL_CURVE_SECP224R1, SSL_CURVE_SECP256R1, SSL_CURVE_SECP384R1,
        SSL_CURVE_SECP521R1};

    std::array<bssl::UniquePtr<EC_GROUP>, 2> groups;
    bssl::Array<bssl::UniquePtr<bssl::SSLKeyShare>> key_shares;
    REQUIRE(key_shares.Init(2));

    for (unsigned i = 0; i < curves.size(); i++) {
      const auto outer_curve = curves[i];
      groups[0].reset(
          EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(outer_curve)));
      REQUIRE(groups[0]);

      for (unsigned j = 0; j < curves.size(); j++) {
        const auto inner_curve = curves[j];
        groups[1].reset(
            EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(inner_curve)));
        REQUIRE(groups[1]);

        // This code mimics the KeyShare creation in extensions.cc
        // ssl_setup_key_shares.
        // NOTE: you need to reset the key shares on each iteration: otherwise
        // the Offer() will fail.
        key_shares[0].reset();
        key_shares[0] = bssl::SSLKeyShare::Create(outer_curve);
        REQUIRE(key_shares[0]);

        key_shares[1].reset();
        key_shares[1] = bssl::SSLKeyShare::Create(inner_curve);
        REQUIRE(key_shares[1]);

        bssl::ScopedCBB cbb;
        CBB key_exchange;
        bssl::Array<uint8_t> key_bytes;

        REQUIRE(CBB_init(cbb.get(), 64));
        REQUIRE(CBB_add_u16(cbb.get(), key_shares[0]->GroupID()));
        REQUIRE(CBB_add_u16_length_prefixed(cbb.get(), &key_exchange));
        REQUIRE(key_shares[0]->Offer(&key_exchange));

        REQUIRE(CBB_add_u16(cbb.get(), key_shares[1]->GroupID()));
        REQUIRE(CBB_add_u16_length_prefixed(cbb.get(), &key_exchange));
        REQUIRE(key_shares[1]->Offer(&key_exchange));
        REQUIRE(CBBFinishArray(cbb.get(), &key_bytes));

        // We now want to generate key shares.
        const auto generated_properly = server.create_new_share(key_bytes);
        CHECK(generated_properly);
        if (generated_properly) {
          // Check that the key share's group IDs are as expected.
          const auto key_share_ids = server.get_curve_ids();
          CHECK(key_share_ids[0] == outer_curve);
          CHECK(key_share_ids[1] == inner_curve);
        }
      }
    }
  }
}

//! [ServerGetAdditiveShareTests]
TEST_CASE("Server get_additive_share tests") {
  Server server(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1",
                false, 1);

  bssl::Array<uint8_t> arr;
  SUBCASE(
      "Calling get_additive_share before generating an additive share works") {
    // First of all we'll resize arr to be greater than size 0.
    REQUIRE(arr.Init(100));
    REQUIRE(arr.size() == 100);
    const auto copied = server.get_additive_share(arr);
    CHECK(copied);
    if (copied) {
      // The additive share should now have size 0
      CHECK(arr.size() == 0);
    }
  }

  SUBCASE(
      "Calling get_additive_share after generating an additive share works") {
    // We'll just choose one curve.
    bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
    REQUIRE(bn_ctx);
    bssl::BN_CTXScope scope(bn_ctx.get());

    constexpr auto curve = SSL_CURVE_SECP224R1;
    bssl::UniquePtr<EC_GROUP> group(
        EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve)));
    REQUIRE(group);
    auto other_party = bssl::SSLKeyShare::Create(curve);
    REQUIRE(other_party);
    bssl::Array<uint8_t> other_key_bytes;
    REQUIRE(Util::generate_public_key(*other_party, other_key_bytes));
    // Now we'll ask the server to generate additive key shares.
    const auto created_properly = server.create_new_share(other_key_bytes);
    CHECK(created_properly);
    // NOTE: we don't check the correctness here (see ServerCreateNewShareTests
    // for that). Our interest here is just that the bytes retrieved are
    // deterministic.
    if (created_properly) {

      // We'll fetch it once and check that it works
      REQUIRE(server.get_additive_share(arr));
      REQUIRE(arr.size() > 0);

      bssl::Array<uint8_t> other;
      constexpr auto repeats = 100;
      for (unsigned i = 0; i < repeats; i++) {
        REQUIRE(server.get_additive_share(other));
        REQUIRE(other.size() == arr.size());
        CHECK(memcmp(other.data(), arr.data(), sizeof(uint8_t) * arr.size()) ==
              0);
      }
    }

    SUBCASE("We can also get a public key") {
      // Generating an additive share implies a public key too!
      bssl::Array<uint8_t> key;
      REQUIRE(key.size() == 0);
      REQUIRE(server.get_public_key(key));
      CHECK(key.size() != 0);
    }
  }
}

//! [ServerCreateNewShareTests]
TEST_CASE("Server create_new_share tests") {
  Server server(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1",
                false, 1);

  // Note: we'll iterate this process over the NIST curves
  std::array<uint16_t, 4> curves{SSL_CURVE_SECP224R1, SSL_CURVE_SECP256R1,
                                 SSL_CURVE_SECP384R1, SSL_CURVE_SECP521R1};
  // and over some number of repetitions, to make it easier to
  // verify that this actually does what we want it to do.
  constexpr auto repeats = 100;

  // Note: defining the CTX here should make it slightly faster to do these
  // tests.
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());
  for (auto curve : curves) {
    const auto nid = Util::get_nid_from_uint16(curve);
    bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(nid));
    REQUIRE(group);
    bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
    REQUIRE(point);
    for (unsigned i = 0; i < repeats; i++) {
      // We have to make new shares on each iteration, because each share
      // can only do a single key exchange.
      auto other_party = bssl::SSLKeyShare::Create(curve);
      REQUIRE(other_party);
      bssl::Array<uint8_t> other_key_bytes;
      REQUIRE(Util::generate_public_key(*other_party, other_key_bytes));
      // Now we'll ask the server to generate additive key shares.
      const auto created_properly = server.create_new_share(other_key_bytes);
      CHECK(created_properly);
      if (created_properly) {
        // We'll manually add the two public key bytes together and check that
        // they produce an identical bit pattern.
        bssl::Array<uint8_t> server_public_key;
        REQUIRE(server.get_public_key(server_public_key));
        // Now we'll add them together
        REQUIRE(Util::EC_point_addition(group.get(), &point, other_key_bytes,
                                        server_public_key, bn_ctx.get()));
        bssl::Array<uint8_t> our_additive_share;
        REQUIRE(Util::ECPointToCBB(curve, group.get(), point.get(),
                                   our_additive_share, bn_ctx.get()));
        bssl::Array<uint8_t> server_additive_share;
        REQUIRE(server.get_additive_share(server_additive_share));
        REQUIRE(our_additive_share.size() == server_additive_share.size());
        CHECK(memcmp(our_additive_share.data(), server_additive_share.data(),
                     sizeof(uint8_t) * our_additive_share.size()) == 0);
      }
    }
  }
}
//! [ServerCreateNewShareTests]

static void server_hs(std::promise<bool> &&res, Server *server) {
  if (!server || !server->accept()) {
    res.set_value(false);
    return;
  }

  if (!server->do_handshake()) {
    res.set_value(false);
    return;
  }

  if (!server->write_handshake_done()) {
    res.set_value(false);
    return;
  }

  res.set_value(true);
  return;
}

static void server_read(std::promise<bool> &&res, Server *server) {
  if (!server->read_keyshare_after_handshake()) {
    res.set_value(false);
    return;
  }

  if (!server->create_new_share()) {
    res.set_value(false);
    return;
  }

  if (!server->send_additive_share()) {
    res.set_value(false);
    return;
  }

  res.set_value(true);
  return;
}

template <bool debug = false> static bool read_handshake(TLSSocket &sock) {
  bssl::Array<uint8_t> arr;
  arr.Init(1);
  if (sock.read(arr.data(), static_cast<int>(arr.size())) != 1) {
    return false;
  }

  CBS cbs;
  CBS_init(&cbs, arr.data(), arr.size());
  uint8_t out;
  return CBS_get_u8(&cbs, &out) &&
         (out == static_cast<uint8_t>(Messaging::MessageHeaders::DONE_HS));
}

static bool read_keyshares(TLSSocket &socket) {

  bssl::Array<uint8_t> ret_arr;
  if (!ret_arr.Init(256)) {
    return false;
  }

  const auto read =
      socket.read(ret_arr.data(), static_cast<int>(ret_arr.size()));
  if (read >= 256 || read < 0) {
    return false;
  }

  ret_arr.Shrink(static_cast<size_t>(read));
  bssl::Array<uint8_t> out;
  Messaging::MessageHeaders header;
  return Messaging::unpack_key_bytes(header, ret_arr, out) &&
         header == Messaging::MessageHeaders::OK;
}

//! [ServerWriteHandshakeDoneTests]
TEST_CASE("Server write_handshake_done tests") {
  // This test case checks that a SSL handshake can be done with the server.
  Server server(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1",
                false, 1);
  uint16_t port_number;
  REQUIRE(server.get_portnumber(&port_number));
  TLSSocket client(server.get_ctx(), false);
  REQUIRE(client.set_ip_v4());
  // Now we'll start the server on another thread.
  std::promise<bool> prom;
  auto res = prom.get_future();
  std::thread t(server_hs, std::move(prom), &server);
  REQUIRE(client.connect_to("127.0.0.1", port_number));
  // We should now have a singular byte on this socket, corresponding to a
  // DONE_HS.
  REQUIRE(read_handshake(client));
  t.join();
  CHECK(res.get());
}
//! [ServerWriteHandshakeDoneTests]

//! [ServerSendAdditiveShareTests]
TEST_CASE("Server send_additive_share tests") {
  // This test case generates a new additive share, writes it out and then
  // checks that the result of reading it back in is what we'd expect it to be.
  Server server(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1",
                false, 1);
  uint16_t port_number;
  REQUIRE(server.get_portnumber(&port_number));
  TLSSocket client(server.get_ctx(), false);
  REQUIRE(client.set_ip_v4());

  // Note: we'll iterate this process over the NIST curves
  std::array<uint16_t, 4> curves{SSL_CURVE_SECP224R1, SSL_CURVE_SECP256R1,
                                 SSL_CURVE_SECP384R1, SSL_CURVE_SECP521R1};

  // Note: defining the CTX here should make it slightly faster to do these
  // tests.
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  // We like to repeat things to make sure it all works.
  constexpr auto repeats = 100;

  SUBCASE("Connection") {
    // Now we'll start the server on another thread.
    std::promise<bool> prom;
    auto res = prom.get_future();

    std::thread t(server_hs, std::move(prom), &server);
    REQUIRE(client.connect_to("127.0.0.1", port_number));
    // We should now have a singular byte on this socket, corresponding to a
    // DONE_HS.

    REQUIRE(read_handshake(client));
    // For we need to join `t` here.
    t.join();
    CHECK(res.get());

    for (auto curve : curves) {
      const auto nid = Util::get_nid_from_uint16(curve);
      bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(nid));
      REQUIRE(group);
      bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
      REQUIRE(point);
      for (unsigned i = 0; i < repeats; i++) {
        // We have to make new shares on each iteration, because each share
        // can only do a single key exchange.
        auto other_party = bssl::SSLKeyShare::Create(curve);
        REQUIRE(other_party);
        bssl::Array<uint8_t> other_key_bytes;
        REQUIRE(Util::generate_public_key(*other_party, other_key_bytes));
        std::promise<bool> r_prom;
        auto fut = r_prom.get_future();
        bssl::Array<uint8_t> arr;
        REQUIRE(Messaging::pack_key_bytes(Messaging::MessageHeaders::COLLECT,
                                          other_key_bytes, arr));
        REQUIRE(client.write(arr.data(), arr.size()));
        std::thread t2(server_read, std::move(r_prom), &server);
        REQUIRE(read_keyshares(client));
        t2.join();
        CHECK(fut.get());
      }
    }
  }
}
//! [ServerSendAdditiveShareTests]

// This function is a thrower to make sure we return to the test thread below at
// an opportune moment.
static void thrower() { throw std::runtime_error("All good"); }

TEST_CASE("The three party handshake works") {
  // This test case is just to make sure that non-ideal three party handshake
  // works. Here's what we'll do: we'll create a prover, a verifier and a
  // server. 
  Server verifier(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1",
                  false, 1);
  Server server(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1",
                false, 1);

  uint16_t v_port_number, s_port_number;
  REQUIRE(verifier.get_portnumber(&v_port_number));
  REQUIRE(server.get_portnumber(&s_port_number));

  // For the sake of this
  // discussion we'll wrap the sockets into one entity.
  struct Prover {
    TLSSocket connection_to_verifier;
    TLSSocket connection_to_server;
  };

  auto pv_ctx = CreateContextWithTestCertificate(TLS_method());
  auto ps_ctx = CreateContextWithTestCertificate(TLS_method());

  Prover prover{TLSSocket(pv_ctx.get(), false), TLSSocket(ps_ctx.get(), false)};
  REQUIRE(prover.connection_to_server.set_ip_v4());
  REQUIRE(prover.connection_to_verifier.set_ip_v4());

  // Now we'll start the verifier on another thread.
  std::promise<bool> prom;
  auto res = prom.get_future();
  std::thread t(server_hs, std::move(prom), &verifier);
  REQUIRE(prover.connection_to_verifier.connect_to("127.0.0.1", v_port_number));
  REQUIRE(read_handshake(prover.connection_to_verifier));
  t.join();
  REQUIRE(res.get());

  // Now we need to set the verifier connection for the outbound
  // connection_to_server. This is so that the right hook gets called.
  // N.B the server is almost immaterial here: it's just to make sure the right
  // sequence of commands inside BoringSSL get executed.
  auto *verifier_ssl_object = prover.connection_to_verifier.get_ssl_object();
  REQUIRE(verifier_ssl_object);
  REQUIRE(
      prover.connection_to_server.set_verifier_connection(verifier_ssl_object));

  // And we also need to set-up the callback too on the connection_to_server.
  REQUIRE(prover.connection_to_server.set_handshake_callback(
      ThreePartyHandshake::three_party_handshake_comm));

  // This means that the hook has been installed.
  // We now run the verifier on its own thread. This is primarily
  // so it can do the exchange in the background.
  std::promise<bool> verifier_prom;
  auto v_fut = verifier_prom.get_future();

  std::thread verifier_thread(server_read, std::move(verifier_prom), &verifier);

  // WARNING: this is a hack.
  // We need the prover to exit after it's done the 3PH code.
  // To do that, we set a callback that'll throw an exception.
  REQUIRE(SSL::set_throw_function(
      prover.connection_to_server.get_ssl_object(), &thrower,
      static_cast<uint8_t>(Messaging::MessageHeaders::OK)));
  try {
    prover.connection_to_server.connect_to("127.0.0.1", s_port_number);
  } catch (std::runtime_error &e) {
  }
  verifier_thread.join();
  CHECK(v_fut.get());
}

static void server_run_run(std::promise<bool> &&res, Server *server,
                           const Server::ServerState stop_state,
                           bool should_print = false,
                           bool should_make_circuits = false) {
  if (!server) {
    res.set_value(false);
    return;
  }

  res.set_value(server->run(stop_state, should_print, should_make_circuits));
  return;
}

//! [ServerRunTests]
TEST_CASE("Run tests") {
  Server verifier(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1",
                  false, 1);
  Server server(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1",
                false, 1);

  uint16_t v_port_number, s_port_number;
  REQUIRE(verifier.get_portnumber(&v_port_number));
  REQUIRE(server.get_portnumber(&s_port_number));
  // For the sake of this
  // discussion we'll wrap the sockets into one entity.
  struct Prover {
    TLSSocket connection_to_verifier;
    TLSSocket connection_to_server;
  };

  auto pv_ctx = CreateContextWithTestCertificate(TLS_method());
  auto ps_ctx = CreateContextWithTestCertificate(TLS_method());

  Prover prover{TLSSocket(pv_ctx.get(), false), TLSSocket(ps_ctx.get(), false)};
  REQUIRE(prover.connection_to_server.set_ip_v4());
  REQUIRE(prover.connection_to_verifier.set_ip_v4());

  // Now we'll start the verifier on another thread.
  std::promise<bool> verifier_promise;
  auto v_fut = verifier_promise.get_future();

  constexpr auto should_print = false;
  constexpr auto should_make_circuits = false;
  
  std::thread verifier_thread(server_run_run, std::move(verifier_promise),
                              &verifier, Server::ServerState::READING_SKS,
                              std::cref(should_print), std::cref(should_make_circuits));
  REQUIRE(prover.connection_to_verifier.connect_to("127.0.0.1", v_port_number));
  REQUIRE(read_handshake(prover.connection_to_verifier));
  // Now we'll connect out to the server.
  // Same hack as before, plus the callback.
  // N.B the server is almost immaterial here: it's just to make sure the right
  // sequence of commands inside BoringSSL get executed.
  auto *verifier_ssl_object = prover.connection_to_verifier.get_ssl_object();
  REQUIRE(verifier_ssl_object);
  REQUIRE(
      prover.connection_to_server.set_verifier_connection(verifier_ssl_object));

  REQUIRE(prover.connection_to_server.set_handshake_callback(
      ThreePartyHandshake::three_party_handshake_comm));
  REQUIRE(SSL::set_throw_function(
      prover.connection_to_server.get_ssl_object(), &thrower,
      static_cast<uint8_t>(Messaging::MessageHeaders::OK)));

  try {
    prover.connection_to_server.connect_to("127.0.0.1", s_port_number);
  } catch (std::runtime_error &e) {
  }

  verifier_thread.join();
  CHECK(v_fut.get());
}
//! [ServerRunTests]

TEST_CASE("ServerRunTestsSendKS") {
  // This is similar to the test case above: the difference
  // is that we also send and receive the keyshare from the server.
  Server verifier(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1",
                  false, 1);
  Server server(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1",
                false, 1);

  uint16_t v_port_number, s_port_number;
  REQUIRE(verifier.get_portnumber(&v_port_number));
  REQUIRE(server.get_portnumber(&s_port_number));
  // For the sake of this
  // discussion we'll wrap the sockets into one entity.
  struct Prover {
    TLSSocket connection_to_verifier;
    TLSSocket connection_to_server;
  };

  auto pv_ctx = CreateContextWithTestCertificate(TLS_method());
  auto ps_ctx = CreateContextWithTestCertificate(TLS_method());

  Prover prover{TLSSocket(pv_ctx.get(), false), TLSSocket(ps_ctx.get(), false)};
  REQUIRE(prover.connection_to_server.set_ip_v4());
  REQUIRE(prover.connection_to_verifier.set_ip_v4());

  // Now we'll start the verifier on another thread.
  std::promise<bool> verifier_promise;
  auto v_fut = verifier_promise.get_future();

  constexpr auto should_print = false;
  constexpr auto should_make_circuits = false;
  
  std::thread verifier_thread(server_run_run, std::move(verifier_promise),
                              &verifier, Server::ServerState::ECTF_WAIT, std::cref(should_print),
                              std::cref(should_make_circuits));
  REQUIRE(prover.connection_to_verifier.connect_to("127.0.0.1", v_port_number));
  REQUIRE(read_handshake(prover.connection_to_verifier));
  // Now we'll connect out to the server.
  // Same hack as before, plus the callback.
  std::promise<bool> server_promise;
  auto s_fut = server_promise.get_future();
  std::thread server_thread(server_hs, std::move(server_promise), &server);

  auto *verifier_ssl_object = prover.connection_to_verifier.get_ssl_object();
  REQUIRE(verifier_ssl_object);
  REQUIRE(
      prover.connection_to_server.set_verifier_connection(verifier_ssl_object));

  REQUIRE(prover.connection_to_server.set_handshake_callback(
      ThreePartyHandshake::three_party_handshake_comm));
  REQUIRE(prover.connection_to_server.set_keyshare_callback(
      ThreePartyHandshake::three_party_handshake_send_received_key_shares));
  REQUIRE(SSL::set_throw_function(
      prover.connection_to_server.get_ssl_object(), &thrower,
      static_cast<uint8_t>(Messaging::MessageHeaders::HS_RECV)));

  try {
    prover.connection_to_server.connect_to("127.0.0.1", s_port_number);
  } catch (std::runtime_error &e) {
  }

  // So now the verifier should have terminated peacefully.
  verifier_thread.join();
  CHECK(v_fut.get());
  // And now we need to detach the server thread.
  // We don't really mind what its state is.
  server_thread.detach();
}

// Warning: this is a hack!
// The server_thread will not necessarily finish the TLS
// handshake in a "normal" way. This is because a true end-to-end test
// might require a more fully-fledged implementation.
// To fix that we add a function here that simply writes the key bytes to arr at
// the opportune moment.
static bssl::Array<uint8_t> server_y_arr, server_x_arr, client_y_arr,
    client_x_arr;
static std::atomic<bool> server_worked{false}, client_worked{false};

static bool write_server_keyshares_to_arr(const bssl::Array<uint8_t> &x,
                                          const bssl::Array<uint8_t> &y) {
  server_worked = server_x_arr.CopyFrom(x) && server_y_arr.CopyFrom(y);
  return server_worked;
}

static bool write_client_keyshares_to_arr(const bssl::Array<uint8_t> &x,
                                          const bssl::Array<uint8_t> &y) {
  client_worked = client_x_arr.CopyFrom(x) && client_y_arr.CopyFrom(y);
  return client_worked;
}

TEST_CASE("secret_derivation") {
  // This server is meant to check whether the
  // derived secrets are "right" when it comes to those that are
  // derived from inside TLS.
  // This follows the following strategy:
  // 1. We establish a handshake between the verifier and the prover.
  // 2. We let the prover reach out and run the handshake as above.
  // 3. We force the prover and the verifier to output their key shares and
  // sum them.
  //
  // This only works because we also force the server to (sometimes) output
  // their key share into a shared location.
  // N.B the "true" here means "set the scope object globally". At most one of these
  // Servers can do this. 
  Server verifier(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1",
                  false, 1);
  Server server(CreateContextWithTestCertificate(TLS_method()), "127.0.0.1",
                false, 1);

  uint16_t v_port_number, s_port_number;
  REQUIRE(verifier.get_portnumber(&v_port_number));
  REQUIRE(server.get_portnumber(&s_port_number));
  // For the sake of this
  // discussion we'll wrap the sockets into one entity.
  struct Prover {
    TLSSocket connection_to_verifier;
    TLSSocket connection_to_server;
  };

  auto pv_ctx = CreateContextWithTestCertificate(TLS_method());
  auto ps_ctx = CreateContextWithTestCertificate(TLS_method());

  Prover prover{TLSSocket(pv_ctx.get(), false), TLSSocket(ps_ctx.get(), false)};
  REQUIRE(prover.connection_to_server.set_ip_v4());
  REQUIRE(prover.connection_to_verifier.set_ip_v4());

  // Now we'll force the server to output its keyshares.
  REQUIRE(SSL::set_write_keyshares_to_arr(server.get_ssl(),
                                          &write_server_keyshares_to_arr));
  REQUIRE(SSL::set_write_keyshares_to_arr(
      prover.connection_to_server.get_ssl_object(),
      &write_client_keyshares_to_arr));

  // Now we'll start the verifier on another thread.
  std::promise<bool> verifier_promise;
  auto v_fut = verifier_promise.get_future();

  constexpr auto should_print = true;
  constexpr auto should_make_circuits = true;
  
  std::thread verifier_thread(server_run_run, std::move(verifier_promise),
                              &verifier, Server::ServerState::DONE, std::cref(should_print),
                              std::cref(should_make_circuits));
  REQUIRE(prover.connection_to_verifier.connect_to("127.0.0.1", v_port_number));
  REQUIRE(read_handshake(prover.connection_to_verifier));
  // Now we'll connect out to the server.
  // Same hack as before, plus the callback.
  std::promise<bool> server_promise;
  auto s_fut = server_promise.get_future();
  std::thread server_thread(server_hs, std::move(server_promise), &server);

  auto *verifier_ssl_object = prover.connection_to_verifier.get_ssl_object();
  REQUIRE(verifier_ssl_object);
  REQUIRE(
      prover.connection_to_server.set_verifier_connection(verifier_ssl_object));

  REQUIRE(prover.connection_to_server.set_handshake_callback(
      ThreePartyHandshake::three_party_handshake_comm));
  REQUIRE(prover.connection_to_server.set_keyshare_callback(
      ThreePartyHandshake::three_party_handshake_send_received_key_shares));
  REQUIRE(prover.connection_to_server.set_derive_shared_secret_callback(
      ThreePartyHandshake::derive_handshake_secret));
  REQUIRE(prover.connection_to_server.set_derive_handshake_keys_callback(
      ThreePartyHandshake::derive_handshake_keys));

  prover.connection_to_server.set_make_circuits();
  
  REQUIRE(SSL::set_throw_function(
      prover.connection_to_server.get_ssl_object(), &thrower,
      static_cast<uint8_t>(Messaging::MessageHeaders::CERTIFICATE_CTX_RECV)));

  try {
    prover.connection_to_server.connect_to("127.0.0.1", s_port_number);
  } catch (std::runtime_error &e) {}

  // So now the verifier should have terminated peacefully.
  verifier_thread.join();
  CHECK(v_fut.get());
  // And now we need to detach the server thread.
  // We don't really mind what its state is.
  server_thread.detach();

  // We want to make sure, though, that the write _did_ happen.
  REQUIRE(server_worked);
  REQUIRE(client_worked);

  // OK, now if the write happened we want to dump the prover and verifier's
  // secrets to make sure they sum to the value the server wrote.
  auto &verifier_key_share = verifier.get_active_share();

  // We also know that the server and the prover wrote their key shares into the
  // different parts of their layouts. The server writes theirs into server_arr.
  // The prover writes theirs into client_arr.
  // Now we just need to convert the keyshares into points and compare them.

  // Assumption: the group is the same.
  const uint16_t group_id = verifier_key_share.get_group_id();
  // Now we'll make the group.
  bssl::UniquePtr<EC_GROUP> group(
      EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(group_id)));
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());
  REQUIRE(group);

  // Now we'll convert these dumped arrays into points.
  bssl::UniquePtr<BIGNUM> prover_y(
      BN_bin2bn(client_y_arr.data(), client_y_arr.size(), nullptr)),
      server_y(BN_bin2bn(server_y_arr.data(), server_y_arr.size(), nullptr)),
      server_x(BN_bin2bn(server_x_arr.data(), server_x_arr.size(), nullptr)),
      prover_x(BN_bin2bn(client_x_arr.data(), client_x_arr.size(), nullptr));

  auto verifier_point = verifier_key_share.secret_to_ec_point();
  REQUIRE(verifier_point);

  // Now we'll turn the server and prover secrets into points.
  bssl::UniquePtr<EC_POINT> server_point(EC_POINT_new(group.get()));
  bssl::UniquePtr<EC_POINT> prover_point(EC_POINT_new(group.get()));
  REQUIRE(server_point);
  REQUIRE(prover_point);

  REQUIRE(EC_POINT_set_affine_coordinates_GFp(group.get(), server_point.get(),
                                              server_x.get(), server_y.get(),
                                              bn_ctx.get()));

  REQUIRE(EC_POINT_set_affine_coordinates_GFp(group.get(), prover_point.get(),
                                              prover_x.get(), prover_y.get(),
                                              bn_ctx.get()));

  bssl::UniquePtr<EC_POINT> sum_of_v_and_p(EC_POINT_new(group.get()));
  REQUIRE(sum_of_v_and_p);
  REQUIRE(EC_POINT_add(group.get(), sum_of_v_and_p.get(), prover_point.get(),
                       verifier_point.get(), bn_ctx.get()));

  CHECK(EC_POINT_cmp(group.get(), sum_of_v_and_p.get(), server_point.get(),
                     bn_ctx.get()) == 0);

  // As an aside: since the ECTF should have been successful, we'll check that
  // too. We know that the verifier will have written its key shares to x_secret
  // and y_secret.
  SUBCASE("ectf_worked") {
    // The verifier will keep their secret in x_secret.
    const auto &verifier_x_secret = verifier.get_x_secret();
    // We also know that the prover will have written theirs to x_key_store.
    const auto &prover_x_secret =
        prover.connection_to_server.get_ssl_object()->x_key_store;

    // Now we'll turn them into bignums.
    BIGNUM *verifier_x_bn = BN_CTX_get(bn_ctx.get());
    BIGNUM *prover_x_bn = BN_CTX_get(bn_ctx.get());
    BIGNUM *sum_of_x = BN_CTX_get(bn_ctx.get());
    BIGNUM *p = BN_CTX_get(bn_ctx.get());

    REQUIRE(verifier_x_bn);
    REQUIRE(prover_x_bn);
    REQUIRE(sum_of_x);
    REQUIRE(p);

    // We get the characteristic of the underlying field for the comparison.
    REQUIRE(
        EC_GROUP_get_curve_GFp(group.get(), p, nullptr, nullptr, bn_ctx.get()));

    REQUIRE(BN_bin2bn(verifier_x_secret.data(), verifier_x_secret.size(),
                      verifier_x_bn));
    REQUIRE(
        BN_bin2bn(prover_x_secret.data(), prover_x_secret.size(), prover_x_bn));
    // Now we'll add them together.
    REQUIRE(BN_mod_add(sum_of_x, verifier_x_bn, prover_x_bn, p, bn_ctx.get()));

    // And finally, check that they add up to the "right" value.
    CHECK(BN_cmp(sum_of_x, server_x.get()) == 0);
  }

  SUBCASE("traffic_secrets worked") {
    // This is just to check that the rest of the throwing worked.
  }
}

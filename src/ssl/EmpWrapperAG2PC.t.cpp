#include "../doctest.h"
#include "EmpWrapperAG2PC.hpp"
#include "TLSSocket.hpp"
#define SOCKET_SETUP
#include "../mta/F2128MtA.hpp"
#include "TestUtil.hpp"

#include <atomic>
#include <iostream>
#include <memory>
#include <thread>

#include "../boringssl/include/openssl/hkdf.h"
#include <emp-ag2pc/2pc.h>
#include <emp-tool/circuits/circuit_file.h>

// Note: these tests (i.e the early ones) are primarily meant to help diagnose
// potential emp bugs. The rest of the tests are a little too high level to
// catch particular issues with our use of emp, and so this is meant to help
// with that.
template <bool dependent>
static void function_work_impl(const int mode, const int socket) {
  // true here means "don't print".
  emp::NetIO io(mode == emp::ALICE ? nullptr : "127.0.0.1", socket, true);
  constexpr auto filepath = EmpWrapperAG2PCConstants::DH_256_FILEPATH;
  REQUIRE(Util::is_valid_filepath(filepath));
  emp::BristolFormat circuit(filepath);
  emp::NetIO *ios[2] = {&io, &io};
  emp::C2PC<emp::NetIO, 1, emp::FerretCOT, true> twopc{ios, mode, 0, &circuit};
  twopc.function_independent();
  if (dependent) {
    twopc.function_dependent();
  }
}

static void function_independent_work(const int mode, const int socket) {
  function_work_impl<false>(mode, socket);
}

static void function_dependent_work(const int mode, const int socket) {
  function_work_impl<true>(mode, socket);
}

TEST_CASE("function-independent") {
  // This function is just meant to check that the function independent setup
  // works properly.
  auto server_work = []() { function_independent_work(emp::BOB, 16000); };
  std::thread server(server_work);
  function_independent_work(emp::ALICE, 16000);
  server.join();
  // This test doesn't really have a success or failure case: we're more
  // interested in checking that there's no errors.
}

TEST_CASE("function_dependent") {
  // This function is just meant to check that the function dependent setup
  // works properly.
  auto server_work = []() { function_dependent_work(emp::BOB, 16000); };

  std::thread server(server_work);
  function_dependent_work(emp::ALICE, 16000);
  server.join();
}

template <uint16_t nid, uint16_t size, unsigned bn_size> struct ParamSet {
  static constexpr auto id = nid;
  static constexpr auto byte_size = size;
  static constexpr auto bit_size = bn_size;
};

// [EmpWrapperAG2PCDeriveDHECircuit]
TEST_SUITE_BEGIN("derive_dhe_circuit");
TEST_CASE_TEMPLATE("derive_dhe_circuit", param,
                   ParamSet<SSL_CURVE_SECP256R1, 32, 256>,
                   ParamSet<SSL_CURVE_SECP384R1, 48, 384>) {

  SUBCASE("is_deterministic") {
    constexpr auto path = (param::id == SSL_CURVE_SECP256R1)
                              ? EmpWrapperAG2PCConstants::DH_256_FILEPATH
                              : EmpWrapperAG2PCConstants::DH_384_FILEPATH;

    emp::BristolFormat bf1(path);
    emp::BristolFormat bf2(path);

    REQUIRE(bf1.n3 == 256);
    REQUIRE(bf1.n2 == param::byte_size * CHAR_BIT);
    REQUIRE(bf1.n1 == param::byte_size * CHAR_BIT);

    emp::block in1[param::byte_size * CHAR_BIT]{emp::zero_block};
    emp::block in2[param::byte_size * CHAR_BIT]{emp::zero_block};

    emp::block out1[256]{emp::zero_block};
    emp::block out2[256]{emp::zero_block};

    emp::setup_plain_prot(false, "test");
    bf1.compute(out1, in1, in2);
    emp::finalize_plain_prot();
    emp::setup_plain_prot(false, "test");
    bf2.compute(out2, in1, in2);
    emp::finalize_plain_prot();

    CHECK(emp::cmpBlock(out1, out2, 256));
  }
}
TEST_SUITE_END();
// [EmpWrapperAG2PCDeriveDHECircuit]

static std::array<bool, 256> run_gcms(const char *const filepath,
                                      const std::array<bool, 256> &key,
                                      const uint64_t v0, const uint64_t v1) {

  emp::setup_plain_prot(false, "test");
  emp::BristolFormat bf(filepath);
  REQUIRE(bf.n3 == 128);
  REQUIRE(bf.n1 == 256);
  REQUIRE(bf.n2 == 256);

  emp::block in1[256], in2[256];
  emp::block out[128];

  // Produce the random ciphertext.
  emp::block circuit_in[256];
  emp::ProtocolExecution::prot_exec->feed(circuit_in, emp::ALICE, key.data(),
                                          128);
  const auto zero = emp::CircuitExecution::circ_exec->public_label(false);
  std::fill(std::begin(circuit_in) + 128, std::end(circuit_in), zero);

  emp::BristolFormat bf2(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");
  emp::block gcm_key_raw[128];
  bf2.compute(gcm_key_raw, circuit_in, circuit_in);

  // Reveal the output and place into a usable array.
  bool outb[128];
  emp::ProtocolExecution::prot_exec->reveal(outb, emp::PUBLIC, gcm_key_raw,
                                            128);

  // Now use the random multiplication mask.
  auto val0 = v0;
  auto val1 = v1;

  bool bob_in[256]{};
  for (unsigned i = 0; i < 64; i++) {
    bob_in[i + 128] = val0 & 1;
    bob_in[i + 192] = val1 & 1;
    val0 >>= 1;
    val1 >>= 1;
  }

  emp::ProtocolExecution::prot_exec->feed(in1, emp::ALICE, key.data(), 256);
  emp::ProtocolExecution::prot_exec->feed(in2, emp::BOB, bob_in, 256);

  bf.compute(out, in2, in1);
  bool out_key[128];
  emp::ProtocolExecution::prot_exec->reveal(out_key, emp::PUBLIC, out, 128);
  emp::finalize_plain_prot();

  std::array<bool, 256> out_ret;
  std::copy(outb, outb + 128, out_ret.begin());
  std::copy(out_key, out_key + 128, out_ret.begin() + 128);
  return out_ret;
}

static emp::block make_block_from_bool(const std::array<bool, 128> &in) {
  uint64_t low{}, high{};
  for (unsigned j = 0; j < 64; j++) {
    low |= (uint64_t(in[j]) << j);
    high |= (uint64_t(in[j + 64]) << j);
  }

  return emp::makeBlock(high, low);
}

static emp::block run_gcm_mult_function(const std::array<bool, 256> &key,
                                        uint64_t v0, uint64_t v1) {

  auto val0 = v0;
  auto val1 = v1;

  std::array<bool, 256> bob_in{};

  for (unsigned i = 0; i < 64; i++) {
    bob_in[i + 128] = val0 & 1;
    bob_in[i + 192] = val1 & 1;
    val0 >>= 1;
    val1 >>= 1;
  }

  // Now load the circuit.
  emp::setup_plain_prot(false, "test");
  emp::BristolFormat bf(EmpWrapperAG2PCConstants::GCM_FILEPATH);
  emp::block in1[256], in2[256];

  // This portion essentially just executes the joint GCM derivation
  // circuit.
  // N.B This has to be this way around to get around the emp-ag2pc specific
  // bug / choice.
  emp::ProtocolExecution::prot_exec->feed(in2, emp::BOB, bob_in.data(), 256);
  emp::ProtocolExecution::prot_exec->feed(in1, emp::ALICE, key.data(), 256);
  emp::block circuit_out[128];
  bf.compute(circuit_out, in2, in1);

  std::array<bool, 128> out_derive;
  emp::ProtocolExecution::prot_exec->reveal(out_derive.data(), emp::PUBLIC,
                                            circuit_out, 128);

  // N.B We close the circuit here to make sure that there's no overlap between
  // this function and the other functions.
  emp::finalize_plain_prot();
  return make_block_from_bool(out_derive);
}

static emp::block run_gcm_manually(const std::array<bool, 256> &key) {
  emp::setup_plain_prot(false, "test");
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");
  emp::block circuit_in[256];
  emp::ProtocolExecution::prot_exec->feed(circuit_in, emp::ALICE, key.data(),
                                          128);
  const auto zero = emp::CircuitExecution::circ_exec->public_label(false);
  std::fill(std::begin(circuit_in) + 128, std::end(circuit_in), zero);
  emp::block gcm_key_raw[128];
  bf.compute(gcm_key_raw, circuit_in, circuit_in);

  // Reveal the raw gcm key.
  std::array<bool, 128> out_gcm;
  emp::ProtocolExecution::prot_exec->reveal(out_gcm.data(), emp::PUBLIC,
                                            gcm_key_raw, 128);
  // N.B We close the circuit here to make sure that there's no overlap between
  // this function and the other functions.
  emp::finalize_plain_prot();
  return make_block_from_bool(out_gcm);
}

TEST_CASE("aes_gcm_circ") {
  // This function just checks that the AES gcm derivation circuit outputs what
  // we'd expect.
  // Namely, this function checks that the non-naive AES gcm derivation circuit
  // produces the same output as the naive variant, and that the non-naive
  // variant outputs the same result as doing the same calculation manually.
  constexpr auto repeats = 100;

  SUBCASE("outputs match") {
    for (unsigned i = 0; i < repeats; i++) {
      // Make the random key + mask for Alice.
      std::array<bool, 256> key;
      std::generate(key.begin(), key.end(),
                    []() { return static_cast<bool>(rand()); });

      // Now we generate Bob's random multiplicative value. Bob only supplies
      // 128 bits of input into the function.
      const auto v0 = static_cast<uint64_t>(rand());
      const auto v1 = static_cast<uint64_t>(rand());

      const auto opt_out =
          run_gcms(EmpWrapperAG2PCConstants::GCM_FILEPATH, key, v0, v1);
      const auto regular_out =
          run_gcms(EmpWrapperAG2PCConstants::GCM_NAIVE_FILEPATH, key, v0, v1);
      CHECK(regular_out == opt_out);
    }
  }

  // Check that the GCM output is as expected. To carry out this test, we
  // invoke our gcm derivation circuit and then compare against the result
  // of doing the same thing manually.
  SUBCASE("as_expected") {
    for (unsigned i = 0; i < repeats; i++) {
      // Generate a random key and mask for Alice.
      std::array<bool, 128> key, mask;
      std::generate(key.begin(), key.end(),
                    []() { return static_cast<bool>(rand()); });
      std::generate(mask.begin(), mask.end(),
                    []() { return static_cast<bool>(rand()); });

      std::array<bool, 256> input;
      std::copy(key.cbegin(), key.cend(), input.begin());
      std::copy(mask.cbegin(), mask.cend(), input.begin() + 128);

      // Now define Bob's random multiplicative value.
      const auto v0 = static_cast<uint64_t>(rand());
      const auto v1 = static_cast<uint64_t>(rand());

      // And now we just call each function to get the results.
      const auto manual_out = run_gcm_manually(input);
      const auto our_out = run_gcm_mult_function(input, v0, v1);

      // Now we take the output of the gcm_mult_function and xor it against
      // Alice's input mask.
      const auto alice_mask = make_block_from_bool(mask);
      const auto actual = alice_mask ^ our_out;

      // N.B Emp's makeBlock takes high then low, so these are the other way
      // around to the call above.
      const auto bob_mask = emp::makeBlock(v1, v0);
      const auto expected = F2128_MTA::mul(bob_mask, manual_out);
      CHECK(emp::cmpBlock(&actual, &expected, 1));
    }
  }
}

TEST_CASE("aes_gcm_derivation") {
  // This function just checks that the shares are as we expect.
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);
  std::unique_ptr<TLSSocket> client, server;
  REQUIRE(setup_sockets(context, server, client));

  std::unique_ptr<EmpWrapperAG2PC> client_circ;
  std::unique_ptr<EmpWrapperAG2PC> server_circ;

  EmpWrapperAG2PC::derive_gcm_input_type server_in, client_in;
  EmpWrapperAG2PC::derive_gcm_secrets_output_type server_out, client_out;

  // Generate random values. We treat the first 128 bits of input as the key
  // share and the last 128 bits as the mask.
  Util::generate_random_bytes<sizeof(client_in)>(client_in.data());
  Util::generate_random_bytes<sizeof(server_in)>(server_in.data());

  auto server_work = [&]() {
    server_circ.reset(EmpWrapperAG2PC::build_gcm_circuit(
        server->get_ssl_object(), emp::ALICE, 0));
    server_circ->do_preproc();
    CHECK(server_circ->derive_gcm_shares(server_in, server_out));
  };

  auto client_work = [&]() {
    client_circ.reset(EmpWrapperAG2PC::build_gcm_circuit(
        client->get_ssl_object(), emp::BOB, 0));
    client_circ->do_preproc();
    CHECK(client_circ->derive_gcm_shares(client_in, client_out));
  };

  std::thread server_thread(server_work);
  client_work();
  server_thread.join();

  // Output values should be the same.
  REQUIRE(server_out == client_out);
}

template <typename T, int mode>
static T *build_handshake_circuit(SSL *const ssl,
                                  const unsigned size) noexcept {
  if (size == EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_256_IN_SIZE) {
    return T::build_derive_hs_256(ssl, mode, 0);
  } else {
    return T::build_derive_hs_384(ssl, mode, 0);
  }
}

template <typename T, int mode>
static T *build_ts_circuit(SSL *const ssl) noexcept {
  return T::build_derive_ts_circuit(ssl, mode, 1);
}

template <typename T, int mode>
static T *build_gcm_circuit(SSL *const ssl) noexcept {
  return T::build_gcm_circuit(ssl, mode, 1);
}

// This function just exists to make producing sublabels easier during
// testing.
static std::array<uint8_t, 32>
produce_sublabel(const std::string &label,
                 const std::array<uint8_t, 32> &input_state,
                 const std::array<uint8_t, 32> &default_hash) noexcept {

  // We always assume SHA256.
  const auto *md = EVP_sha256();
  REQUIRE(md);

  // If we're expanding then we also need to feed that output secret
  // into the expand_label code.
  const std::string protocol_label = "tls13 ";
  bssl::ScopedCBB cbb;
  CBB child;

  // The empty_hash is fixed.
  static constexpr std::array<unsigned char, 32> empty_hash{
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
      0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
      0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

  const unsigned char *tmp_hash;
  unsigned tmp_hash_size;
  unsigned hash_output_size;

  // Now choose the right temporary input.
  // N.B This can't be a switch, because C++.
  if (label == "finished" || label == "iv" || label == "key" || label == "iv") {
    tmp_hash = nullptr;
    tmp_hash_size = 0;

    if (label == "key") {
      hash_output_size = 16;
    } else if (label == "finished") {
      hash_output_size = 32;
    } else {
      hash_output_size = 12;
    }
  } else if (label == "derived") {
    tmp_hash = empty_hash.data();
    tmp_hash_size = empty_hash.size();
    hash_output_size = 32;
  } else {
    const auto is_valid = (label == "s hs traffic" || label == "c hs traffic" ||
                           label == "s ap traffic" || label == "c ap traffic");
    REQUIRE(is_valid);
    tmp_hash = default_hash.data();
    tmp_hash_size = unsigned(default_hash.size());
    hash_output_size = 32;
  }

  bssl::Array<uint8_t> hkdf_label;
  if (!CBB_init(cbb.get(),
                2 + 1 + label.size() + protocol_label.size() + 1 + 32) ||
      !CBB_add_u16(cbb.get(), uint16_t(hash_output_size)) ||
      !CBB_add_u8_length_prefixed(cbb.get(), &child) ||
      !CBB_add_bytes(&child,
                     reinterpret_cast<const uint8_t *>(protocol_label.data()),
                     protocol_label.size()) ||
      !CBB_add_bytes(&child, reinterpret_cast<const uint8_t *>(label.data()),
                     label.size()) ||
      !CBB_add_u8_length_prefixed(cbb.get(), &child) ||
      !CBB_add_bytes(&child, tmp_hash, tmp_hash_size) ||
      !CBBFinishArray(cbb.get(), &hkdf_label)) {
    REQUIRE(false);
  }

  std::array<unsigned char, 32> tmp_hash_out;
  REQUIRE(HKDF_expand(tmp_hash_out.data(), hash_output_size, md,
                      input_state.data(), input_state.size(), hkdf_label.data(),
                      hkdf_label.size()));

  return tmp_hash_out;
}

// [EmpWrapperAG2PCDeriveCombinedSecrets]
TEST_SUITE_BEGIN("derive_combined_handshake");
TEST_CASE_TEMPLATE(
    "derive_combined_handshake", param,
    ParamSet<SSL_CURVE_SECP256R1,
             EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_256_IN_SIZE, 256>,
    ParamSet<SSL_CURVE_SECP384R1,
             EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_384_IN_SIZE, 384>) {
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);
  std::unique_ptr<TLSSocket> client, server;
  REQUIRE(setup_sockets(context, server, client));

  std::unique_ptr<EmpWrapperAG2PC> client_circ;
  std::unique_ptr<EmpWrapperAG2PC> server_circ;

  // bssl's Array fill these initially with random data. Each subtest can
  // change these as appropriate.
  std::array<uint8_t, param::byte_size> client_in;
  std::array<uint8_t, param::byte_size> server_in;

  // We'll always output this many bytes for combined derivation circuits.
  constexpr auto out_size =
      EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_OUTPUT_SIZE;

  std::array<uint8_t, out_size> client_out;
  std::array<uint8_t, out_size> server_out;

  auto server_work = [&]() {
    server_circ.reset(build_handshake_circuit<EmpWrapperAG2PC, emp::BOB>(
        server->get_ssl_object(), param::byte_size));
    server_circ->do_preproc();
    CHECK(server_circ->derive_hs(server_in, server_out));
  };

  auto client_work = [&]() {
    client_circ.reset(build_handshake_circuit<EmpWrapperAG2PC, emp::ALICE>(
        client->get_ssl_object(), param::byte_size));
    client_circ->do_preproc();
    CHECK(client_circ->derive_hs(client_in, client_out));
  };

  SUBCASE("empty params") {
    std::fill(client_in.begin(), client_in.end(), 0);
    std::fill(server_in.begin(), server_in.end(), 0);

    std::thread thread(server_work);
    client_work();
    thread.join();

    // The output size should be correct.
    // It's always exactly out_size bytes.
    CHECK(client_out.size() == out_size);
    CHECK(server_out.size() == out_size);

    SUBCASE("is deterministic") {
      const auto copy_cout = client_out;
      const auto copy_sout = server_out;

      std::fill(client_out.begin(), client_out.end(), 0);
      std::fill(server_out.begin(), server_out.end(), 0);
      std::thread threadd(server_work);
      client_work();
      threadd.join();

      CHECK(client_out == copy_cout);
      CHECK(server_out == copy_sout);
    }
  }

  SUBCASE("is_correct") {
    std::fill(client_in.begin(), client_in.end(), 0);
    std::fill(server_in.begin(), server_in.end(), 0);

    bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
    REQUIRE(bn_ctx);
    bssl::BN_CTXScope scope(bn_ctx.get());

    BIGNUM *a = BN_CTX_get(bn_ctx.get());
    BIGNUM *b = BN_CTX_get(bn_ctx.get());
    BIGNUM *sum = BN_CTX_get(bn_ctx.get());
    BIGNUM *p = BN_CTX_get(bn_ctx.get());

    REQUIRE(a);
    REQUIRE(b);

    REQUIRE(sum);
    REQUIRE(BN_rand(a, param::bit_size, -1, 0));
    REQUIRE(BN_rand(b, param::bit_size, -1, 0));

    bssl::UniquePtr<EC_GROUP> curve(
        EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(param::id)));
    REQUIRE(curve);

    REQUIRE(
        EC_GROUP_get_curve_GFp(curve.get(), p, nullptr, nullptr, bn_ctx.get()));

    REQUIRE(BN_mod_add(sum, a, b, p, bn_ctx.get()));

    constexpr std::array<uint8_t, 32> dES{
        0x6F, 0x26, 0x15, 0xA1, 0x08, 0xC7, 0x02, 0xC5, 0x67, 0x8F, 0x54,
        0xFC, 0x9D, 0xBA, 0xB6, 0x97, 0x16, 0xC0, 0x76, 0x18, 0x9C, 0x48,
        0x25, 0x0C, 0xEB, 0xEA, 0xC3, 0x57, 0x6C, 0x36, 0x11, 0xBA};

    bssl::Array<uint8_t> arr;
    const auto width = param::bit_size / 8;
    REQUIRE(arr.Init(width));
    REQUIRE(BN_bn2bin_padded(arr.data(), arr.size(), sum));

    // The output is always 256 bits. Note that the
    // BoringSSL output is already in the right order.
    std::array<unsigned char, 32> output_hash{};
    size_t len;
    const auto *md = EVP_sha256();
    REQUIRE(md);
    REQUIRE(HKDF_extract(output_hash.data(), &len, md, arr.data(), arr.size(),
                         dES.data(), dES.size()));

    // Choose a random hash value.
    std::array<uint8_t, 32> h2{};
    for (unsigned i = 0; i < 32; i++) {
      h2[i] = static_cast<uint8_t>(rand());
    }

    // Now we start packing. We do this from 0.
    // NOTE: The h2 input is fed in by Alice, which (in this case) corresponds
    // to the client.
    std::copy(h2.cbegin(), h2.cend(), client_in.begin());

    // Now we can pack in the hash mask.
    // This mask is HANDSHAKE_MASK_SIZE bytes for each party.
    std::array<uint8_t, EmpWrapperAG2PCConstants::HANDSHAKE_MASK_SIZE>
        client_mask;
    std::array<uint8_t, EmpWrapperAG2PCConstants::HANDSHAKE_MASK_SIZE>
        server_mask;

    for (unsigned i = 0; i < client_mask.size(); i++) {
      client_in[32 + i] = client_mask[i] = static_cast<uint8_t>(rand());
      server_in[32 + i] = server_mask[i] = static_cast<uint8_t>(rand());
    }

    // We just pack everything "as is". Note that our circuits expect little
    // endian inputs for summation, and thus we simply deserialise these
    // values as little endian.
    constexpr auto offset = 32 + EmpWrapperAG2PCConstants::HANDSHAKE_MASK_SIZE;
    REQUIRE(BN_bn2le_padded(client_in.data() + offset, param::bit_size / 8, a));
    REQUIRE(BN_bn2le_padded(server_in.data() + offset, param::bit_size / 8, b));

    // Run the circuit again.
    std::thread thread(server_work);
    client_work();
    thread.join();

    // The outputs will not be identical. Instead, we need to copy the outputs
    // into a single, larger buffer, which will have the right outputs.
    REQUIRE(client_out == server_out);

    // XOR the client output appropriately. The first 16 of each set of 32
    // bytes were xor'd against the client's mask, whereas the second 16 were
    // xor'd against the server's mask.
    unsigned pos{};
    for (unsigned i = 0; i < 5; i++) {
      // We extract the i-th secret
      for (unsigned j = 0; j < 16; j++) {
        client_out[i * 32 + j] ^= client_mask[pos];
        client_out[i * 32 + j + 16] ^= server_mask[pos];
        ++pos;
      }
    }

    REQUIRE(pos == EmpWrapperAG2PCConstants::HANDSHAKE_MASK_SIZE - 16);

    // The first 16 of each set of 32 bytes were xor'd against the client's
    // mask, whereas the second 16 were xor'd against the server's mask.
    SUBCASE("HS") {
      CHECK(memcmp(client_out.data(), output_hash.data(),
                   sizeof(output_hash)) == 0);
    }

    const auto produce_sublabel_output_hash = [&output_hash,
                                               &h2](const std::string &label) {
      return produce_sublabel(label, output_hash, h2);
    };

    // These just check the derivation of each sub secret.
    SUBCASE("CHTS") {
      const auto chts = produce_sublabel_output_hash("c hs traffic");
      CHECK(memcmp(client_out.data() + 32, chts.data(), sizeof(output_hash)) ==
            0);
    }

    SUBCASE("SHTS") {
      const auto shts = produce_sublabel_output_hash("s hs traffic");
      CHECK(memcmp(client_out.data() + 64, shts.data(), sizeof(output_hash)) ==
            0);
    }

    // The DHS is special, because we need to make sure that it has happened
    // before checking the MS etc.
    SUBCASE("derived") {
      const auto dHS = produce_sublabel_output_hash("derived");
      REQUIRE(memcmp(client_out.data() + 96, dHS.data(), sizeof(output_hash)) ==
              0);

      // Now the rest.
      SUBCASE("ms") {
        // The MS is acquired by applying HDKF_Extract to the dHS with an all
        // zero hash.
        constexpr std::array<uint8_t, 32> zeroes{};
        std::array<uint8_t, 32> ms;
        REQUIRE(HKDF_extract(ms.data(), &len, md, zeroes.data(), zeroes.size(),
                             dHS.data(), dHS.size()));
        REQUIRE(len == ms.size());
        CHECK(memcmp(client_out.data() + 128, ms.data(), sizeof(ms)) == 0);
      }

      // Everything after here requires the SHTS.
      const auto shts = produce_sublabel_output_hash("s hs traffic");
      // Should have been covered by an earlier test case.
      REQUIRE(memcmp(client_out.data() + 64, shts.data(), sizeof(shts)) == 0);

      // N.B h2 isn't actually used in any of these, it's just here to satisfy
      // the API.
      SUBCASE("fk_s") {
        const auto fks = produce_sublabel("finished", shts, h2);
        CHECK(memcmp(client_out.data() + 160, fks.data(), sizeof(fks)) == 0);
      }

      SUBCASE("key") {
        // The last load of bytes are masked against the client input key.
        for (unsigned i = 0; i < 16; i++) {
          client_out[192 + i] ^= client_mask[80 + i];
        }

        const auto key = produce_sublabel("key", shts, h2);
        CHECK(memcmp(client_out.data() + 192, key.data(), 16) == 0);
      }

      SUBCASE("iv") {
        const auto iv = produce_sublabel("iv", shts, h2);
        CHECK(memcmp(client_out.data() + 208, iv.data(), 12) == 0);
      }
    }
  }
}
TEST_SUITE_END();
// [EmpWrapperAG2PCDeriveCombined]

TEST_CASE("derive_combined_traffic") {
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);
  std::unique_ptr<TLSSocket> client, server;
  REQUIRE(setup_sockets(context, server, client));

  std::unique_ptr<EmpWrapperAG2PC> client_circ;
  std::unique_ptr<EmpWrapperAG2PC> server_circ;

  // bssl's Array fill these initially with random data. Each subtest can
  // change these as appropriate. N.B The full size of the input is in
  // TRAFFIC_SECRETS_IN_SIZE.
  constexpr auto input_size = EmpWrapperAG2PCConstants::TRAFFIC_SECRETS_IN_SIZE;

  std::array<uint8_t, input_size> client_in{};
  std::array<uint8_t, input_size> server_in{};

  // We'll always output this many bytes for combined derivation circuits.
  constexpr auto out_size =
      EmpWrapperAG2PCConstants::TRAFFIC_SECRETS_OUTPUT_SIZE;

  std::array<uint8_t, out_size> client_out{};
  std::array<uint8_t, out_size> server_out{};

  auto server_work = [&]() {
    server_circ.reset(
        build_ts_circuit<EmpWrapperAG2PC, emp::BOB>(server->get_ssl_object()));
    server_circ->do_preproc();
    CHECK(server_circ->derive_ts(server_in, server_out));
  };

  auto client_work = [&]() {
    client_circ.reset(build_ts_circuit<EmpWrapperAG2PC, emp::ALICE>(
        client->get_ssl_object()));
    client_circ->do_preproc();
    CHECK(client_circ->derive_ts(client_in, client_out));
  };

  // Now check for correctness by running the circuit on random inputs.
  // As before, the inputs are:
  // 1) a random master secret.
  // 2) a random h3 value.
  // 3) a random mask each.

  // The first 16 bytes each are the random master secrets.
  // Bob holds the second 16 bytes, Alice holds the first 16.

  const auto gen_secret = [&client_in, &server_in](const unsigned offset) {
    std::array<uint8_t, 32> out{};
    for (unsigned i = 0; i < 32; i++) {
      out[i] = static_cast<uint8_t>(rand());
    }

    std::copy(out.cbegin(), out.cbegin() + 16, client_in.begin() + offset);
    std::copy(out.cbegin() + 16, out.cend(), server_in.begin() + offset);
    return out;
  };

  // Make the secret.
  const auto ms = gen_secret(0);

  // The next 32 bytes are just Alice's input hash.
  std::array<uint8_t, 32> h3;
  for (unsigned i = 0; i < 32; i++) {
    client_in[16 + i] = h3[i] = static_cast<uint8_t>(rand());
  }

  // NOTE: only the client mask is actually used in the circuits.
  std::array<uint8_t, EmpWrapperAG2PCConstants::TRAFFIC_MASK_SIZE> client_mask;

  for (unsigned i = 0; i < client_mask.size(); i++) {
    client_in[48 + i] = client_mask[i] = static_cast<uint8_t>(rand());
  }

  SUBCASE("same each") {
    std::thread threadd(server_work);
    client_work();
    threadd.join();
    CHECK(client_out == server_out);

    SUBCASE("is_deterministic") {
      const auto client_old{client_out};
      const auto server_old{server_out};
      std::thread threadd2(server_work);
      client_work();
      threadd2.join();
      REQUIRE(client_out == server_out);
      CHECK(client_out == client_old);
      CHECK(server_out == server_old);
    }
  }

  // Same as expected.
  SUBCASE("same as boringssl") {
    // This one is far easier: we just need to compute the various expansions
    // and compare. N.B Each output secret is xored against the client mask
    // so we repeat the work and then undo the xor.
    std::thread threadd(server_work);
    client_work();
    threadd.join();
    REQUIRE(client_out == server_out);
    for (unsigned i = 0; i < 16; i++) {
      client_out[i] ^= client_mask[i];
    }

    for (unsigned i = 28; i < 44; i++) {
      client_out[i] ^= client_mask[i - 12];
    }

    // Now produce the CATS / SATS etc.
    const auto sats = produce_sublabel("s ap traffic", ms, h3);
    const auto cats = produce_sublabel("c ap traffic", ms, h3);

    SUBCASE("client key") {
      const auto client_key = produce_sublabel("key", cats, h3);
      // The client key is in the first 16 bytes of the client out.
      CHECK(memcmp(client_out.data(), client_key.data(),
                   sizeof(client_key) / 2) == 0);
    }

    SUBCASE("client iv") {
      const auto client_iv = produce_sublabel("iv", cats, h3);
      // The client iv is in the next 12 bytes of the client out.
      CHECK(memcmp(client_out.data() + 16, client_iv.data(), 12) == 0);
    }

    SUBCASE("server key") {
      const auto server_key = produce_sublabel("key", sats, h3);
      // The server key is in the next 16 bytes of the client out.
      CHECK(memcmp(client_out.data() + 28, server_key.data(),
                   sizeof(server_key) / 2) == 0);
    }

    SUBCASE("server iv") {
      const auto server_iv = produce_sublabel("iv", sats, h3);
      // The server key is in the last 12 bytes of the client out.
      CHECK(memcmp(client_out.data() + 44, server_iv.data(), 12) == 0);
    }
  }
}

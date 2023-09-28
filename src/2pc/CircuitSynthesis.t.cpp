#include "../boringssl/include/openssl/hkdf.h"
#include "../doctest.h"
#include "../ssl/Util.hpp"
#include "CircuitSynthesis.hpp"

//! [CircuitSynthesisGetK]
TEST_CASE("get_k") {
  SUBCASE("Produces 0") {
    // We just check that if L + 1 + 64 is a multiple of 512, we
    // get 0 as a result.
    // To do this, we write L = k * 512 - (65)
    for (unsigned k = 1; k < 10; k++) {
      const auto L = k * 512 - 65;
      CHECK(CircuitSynthesis::get_K(L) == 0);
    }
  }

  SUBCASE("general_case") {
    // This checks that 512t = len + 1 + K + 64 for some `t`.
    static constexpr auto repeats = 1024;
    for (unsigned i = 0; i < repeats; i++) {
      // Make sure it fits easily.
      const auto len = static_cast<unsigned>(rand() % 4096);
      const auto k = CircuitSynthesis::get_K(len);
      CHECK((len + 1 + k + 64) % 512 == 0);
    }
  }
}
//! [CircuitSynthesisGetK]

//! [CircuitSynthesisGetPaddedLen]
TEST_CASE("get_padded_len") {
  static constexpr auto repeats = 1024;
  for (unsigned i = 0; i < repeats; i++) {
    CHECK(CircuitSynthesis::get_padded_len(i) % 512 == 0);
  }
}
//! [CircuitSynthesisGetPaddedLen]

//! [CircuitSynthesisReverseBytes]
TEST_CASE("reverse_bytes") {
  // We just allocate a random number of blocks and iterate over them
  // backwards.
  static constexpr auto length = 128;

  emp::block *b0 = new emp::block[length];
  emp::block *b1 = new emp::block[length];

  emp::PRG prg(emp::fix_key);
  prg.random_block(b0, length);
  memcpy(b1, b0, sizeof(emp::block) * length);
  EmpBlockNonOwningSpan ens(b1, length);
  CircuitSynthesis::reverse_bytes(ens);

  for (unsigned i = 0; i < length; i++) {
    CHECK(emp::cmpBlock(&b0[i], &b1[length - i - 1], 1));
  }

  delete[] b0;
  delete[] b1;
}
//! [CircuitSynthesisReverseBytes]

static void change_endian_n_for_1_auth(emp::block *input, emp::block *output,
                                       int input_len) {
  if (input_len % CHAR_BIT != 0) {
    emp::error(
        "The circuit synthesizer can only convert the endianness for bytes.");
  }

  int num_bytes = input_len / CHAR_BIT;
  for (int i = 0; i < num_bytes; i++) {
    for (int j = 0; j < CHAR_BIT; j++) {
      output[i * CHAR_BIT + j] = input[i * CHAR_BIT + (7 - j)];
    }
  }
}

//! [CircuitSynthesisChangeEndian]
TEST_CASE("change_endian") {

  static constexpr auto length = 128;
  static constexpr auto inner_length = 8;
  static_assert(length % inner_length == 0,
                "Error: must have inner_length | length");
  static constexpr auto nr_blocks = length / inner_length;

  // We allocate a block of a fixed length and then check that the reversed
  // version is as expected.
  EmpBlockOwningSpan b0(length), r(length), b1(inner_length);
  emp::PRG prg(emp::fix_key);
  prg.random_block(b1.data(), inner_length);

  // Copy over the inner block into the larger block.
  for (unsigned i = 0; i < length / inner_length; i++) {
    std::copy(b1.cbegin(), b1.cend(), b0.begin() + (i * inner_length));
  }

  CircuitSynthesis::change_endian(b0, r.data());

  for (unsigned i = 0; i < nr_blocks; i++) {
    auto r_iter = &r[i * inner_length];
    auto b1_iter = &b1[inner_length - 1];
    for (unsigned j = 0; j < inner_length; j++) {
      CHECK(emp::cmpBlock(r_iter, b1_iter, 1));
      ++r_iter;
      --b1_iter;
    }
  }

  SUBCASE("same as n-for-1-auth") {
    emp::block *b2 = new emp::block[length];
    change_endian_n_for_1_auth(b0.data(), b2, length);
    CHECK(emp::cmpBlock(b2, r.data(), length));
    delete[] b2;
  }
}
//! [CircuitSynthesisChangeEndian]

//! [CircuitSynthesisPadding]
TEST_CASE("CircuitSynthesisPadding") {
  emp::setup_plain_prot(false, "test_padding.txt");
  static constexpr unsigned length = 128;

  EmpBlockOwningSpan b0(length);
  emp::PRG prg(emp::fix_key);
  prg.random_block(b0.data(), length);

  const auto K = CircuitSynthesis::get_K(length);
  const auto upper = length + 1 + K + 64;

  EmpBlockOwningSpan b1(upper);
  CircuitSynthesis::padding(b0, b1.data());

  // We'll get the public labels too.
  emp::block one = emp::CircuitExecution::circ_exec->public_label(true);
  emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);

  // Now we'll check the output. The first `0 : length - 1` should be `input`.
  CHECK(emp::cmpBlock(&b1[0], &b0[0], length));

  // The "next" one should be the `0` label.
  CHECK(emp::cmpBlock(&b1[length], &one, 1));

  // The next K + 48 entries should be `zero`.
  for (unsigned i = 0; i < K + 48; i++) {
    CHECK(emp::cmpBlock(&b1[length + 1 + i], &zero, 1));
  }

  const auto start_of_end = length + 1 + K + 48;
  for (unsigned i = 0; i < 16; i++) {
    const auto is_set = (length & (1 << (16 - 1 - i))) != 0;
    if (is_set) {
      CHECK(emp::cmpBlock(&b1[start_of_end + i], &one, 1));
    } else {
      CHECK(emp::cmpBlock(&b1[start_of_end + i], &zero, 1));
    }
  }

  emp::finalize_plain_prot();
}
//! [CircuitSynthesisPadding]

static void n_for_1_auth_reversal(const emp::block *const input,
                                  emp::block *const output) {

  // This algorithm essentially just swaps the block inputs.
  // In particular, we have that output[0:7, 8:15, 16:23, 24:31] =
  //                             input[24:31, 16:23, 8:15, 0:7]

  // You can produce this by hand:

  // output[0] = input[24]   <---|
  // ...                         |--- i = 0, j = 0
  // output[7] = input[31]   <---|

  // output[8] = input[16]   <---|
  // ...                         |--- i = 0, j = 1
  // output[15] = input[23]  <---|

  // output[16] = input[8]   <---|
  // ...                         |--- i = 0, j = 2
  // output[23] = input[15]  <---|

  // output[24] = input[0]   <---|
  // ...                         |--- i = 0, j = 3
  // output[31] = input[7]   <---|

  // output[32] = input[56]  <---|
  // ...                         |--- i = 1, j = 0
  // output[39] = input[63]  <---|

  // output[40] = input[48]  <---|
  // ...                         |--- i = 1, j = 1
  // output[47] = input[55]  <---|

  // output[48] = input[40]  <---|
  // ...                         |--- i = 1, j = 2
  // output[56] = input[47]  <---|

  // output[57] = input[32]  <---|
  // ...                         |--- i = 1, j = 3
  // output[63] = input[40]  <---|

  // etc etc

  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < 4; j++) {
      for (int k = 0; k < 8; k++) {
        output[i * 32 + j * 8 + k] = input[i * 32 + 8 * (3 - j) + k];
      }
    }
  }
}

TEST_CASE("check_reversal") {
  // This just checks that the n_for_1_auth_reversal in fact just changes the
  // endianness.
  static constexpr auto length = 256;
  EmpBlockOwningSpan b0(length), b1(length), b2(length);

  emp::PRG prg(emp::fix_key);
  prg.random_block(b0.data(), length);

  CircuitSynthesis::change_endian_four(b0.data(), b1.data());
  n_for_1_auth_reversal(b0.data(), b2.data());
  CHECK(emp::cmpBlock(b1.data(), b2.data(), length));
}

template <unsigned long size = 32>
static std::array<unsigned char, size>
print_hash_to_string(const emp::block *const output) {
  unsigned char digest_char[size];
  memset(digest_char, 0, size);

  bool output_bool[size * 8];
  emp::ProtocolExecution::prot_exec->reveal(output_bool, emp::PUBLIC, output,
                                            size * 8);

  unsigned curr{};
  for (unsigned i = 0; i < size; i++) {
    uint8_t tmp{};
    for (unsigned j = 0; j < 8; j++) {
      tmp += static_cast<uint8_t>(output_bool[curr] << j);
      ++curr;
    }

    digest_char[i] = tmp;
  }

  std::array<unsigned char, size> out;
  memcpy(out.data(), digest_char, sizeof(digest_char));
  return out;
}

TEST_CASE("sha256") {

  emp::setup_plain_prot(false, "test_sha256.txt");
  emp::block output1[256];
  emp::block output2[256];
  const emp::block one = emp::CircuitExecution::circ_exec->public_label(true);
  const emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);

  // This is just a neater way of wrapping these cases
  struct TestCase {
    EmpBlockOwningSpan input;
    unsigned char hash_out[32];

    TestCase(emp::block entry, const unsigned length,
             const unsigned char *const out)
        : input{length}, hash_out{} {
      std::fill(input.begin(), input.end(), entry);
      memcpy(hash_out, out, 32);
    }
  };

  // These exact answers came from n-for-1-auth's sha256_test function.
  constexpr static unsigned char all_zero_out[]{
      0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4,
      0xC8, 0x99, 0x6F, 0xB9, 0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B,
      0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55};

  constexpr static unsigned char all_one_out_256[]{
      0xAF, 0x96, 0x13, 0x76, 0x0F, 0x72, 0x63, 0x5F, 0xBD, 0xB4, 0x4A,
      0x5A, 0x0A, 0x63, 0xC3, 0x9F, 0x12, 0xAF, 0x30, 0xF9, 0x50, 0xA6,
      0xEE, 0x5C, 0x97, 0x1B, 0xE1, 0x88, 0xE8, 0x9C, 0x40, 0x51};

  constexpr static unsigned char all_one_out_512[]{
      0x86, 0x67, 0xE7, 0x18, 0x29, 0x4E, 0x9E, 0x0D, 0xF1, 0xD3, 0x06,
      0x00, 0xBA, 0x3E, 0xEB, 0x20, 0x1F, 0x76, 0x4A, 0xAD, 0x2D, 0xAD,
      0x72, 0x74, 0x86, 0x43, 0xE4, 0xA2, 0x85, 0xE1, 0xD1, 0xF7};

  constexpr static unsigned char all_one_out_1024[]{
      0xE9, 0x17, 0x5D, 0xB6, 0x5A, 0x97, 0x89, 0x09, 0x6C, 0xA9, 0xCB,
      0x55, 0x24, 0xD3, 0xAB, 0xC2, 0x10, 0x7D, 0xF0, 0x3E, 0x3C, 0x9B,
      0xA3, 0xAF, 0x1A, 0xCA, 0x62, 0x8F, 0x9C, 0x5D, 0x3B, 0xD2};

  TestCase all_zeroes(zero, 0, all_zero_out);
  TestCase all_one_256(one, 256, all_one_out_256);
  TestCase all_one_512(one, 512, all_one_out_512);
  TestCase all_one_1024(one, 1024, all_one_out_1024);

  // This is the actual runner -- just in one place to make life easier.
  auto test_code = [&](const TestCase &test_case) {
    // Known answer test portion.
    EmpBlockOwningSpan input(test_case.input.size());
    std::copy(test_case.input.cbegin(), test_case.input.cend(), input.begin());
    CircuitSynthesis::sha256(input, output1);

    const auto out_str = print_hash_to_string(output1);
    CHECK(memcmp(out_str.data(), test_case.hash_out, 32) == 0);

    // Duplication test portion.
    CircuitSynthesis::sha256(input, output2);
    CHECK(emp::cmpBlock(output1, output2, 256));
  };

  SUBCASE("check that SHA is deterministic on all 0s") {
    test_code(all_zeroes);
  }

  SUBCASE("check that SHA is determininstic on all 1s (256)") {
    test_code(all_one_256);
  }

  SUBCASE("check that SHA is deterministic on all 1s (512)") {
    test_code(all_one_512);
  }

  SUBCASE("check that SHA is deterministic on all 1s (1024)") {
    test_code(all_one_1024);
  }

  emp::finalize_plain_prot();
}

TEST_CASE("hmac") {
  emp::setup_plain_prot(false, "test_hmac.txt");
  EmpBlockOwningSpan key(256);
  const emp::block one = emp::CircuitExecution::circ_exec->public_label(true);
  const emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);
  // We're always going to use the all `1` key.
  std::fill(key.begin(), key.end(), one);

  emp::block output1[256];
  emp::block output2[256];

  // This is just a neater way of wrapping these cases
  struct TestCase {
    EmpBlockOwningSpan input;
    unsigned char hash_out[32];

    TestCase(emp::block entry, const unsigned length,
             const unsigned char *const out)
        : input{length}, hash_out{} {
      std::fill(input.begin(), input.end(), entry);
      memcpy(hash_out, out, 32);
    }
  };

  // These known answer portions come from n-for-1-auth.
  static constexpr unsigned char all_zero_out[]{
      0xB2, 0x0A, 0xE8, 0x0E, 0x1D, 0x70, 0xF4, 0x9E, 0x9B, 0xB5, 0x66,
      0x25, 0xA4, 0xC9, 0xCF, 0x02, 0xA5, 0x54, 0x7B, 0xD2, 0xE2, 0xEF,
      0x7C, 0xF0, 0x65, 0x7E, 0x59, 0xF4, 0x4C, 0xC0, 0xC0, 0x17};
  static constexpr unsigned char all_one_out_256[]{
      0x8A, 0x51, 0x83, 0xC8, 0x7D, 0xC4, 0xE6, 0x94, 0xCD, 0x5D, 0x35,
      0x87, 0x0E, 0xDC, 0x9B, 0x2F, 0xBE, 0x05, 0xC7, 0x1D, 0xBF, 0x9C,
      0x5B, 0x17, 0x64, 0x8A, 0x25, 0xF8, 0x16, 0xFE, 0x29, 0x2D};

  static constexpr unsigned char all_one_out_512[]{
      0x6C, 0x2B, 0x15, 0xF1, 0xFB, 0x87, 0x76, 0x78, 0x3D, 0xB9, 0xC2,
      0xA6, 0x77, 0xCE, 0xBE, 0x12, 0x34, 0x4E, 0x93, 0x64, 0x0A, 0xC0,
      0xD6, 0x7C, 0xB6, 0xE1, 0x57, 0xAB, 0xF8, 0xFC, 0x0D, 0x3A};

  static constexpr unsigned char all_one_out_1024[]{
      0x60, 0x12, 0x88, 0x7C, 0x1A, 0x69, 0xA9, 0x6E, 0x57, 0x04, 0x48,
      0xE0, 0xB2, 0x59, 0x23, 0x1E, 0x46, 0x28, 0xD3, 0x75, 0xB5, 0xB0,
      0x2E, 0x64, 0x51, 0x1B, 0xF6, 0xBA, 0x82, 0x4E, 0x1F, 0xCA};

  TestCase all_zeroes(zero, 0, all_zero_out);
  TestCase all_one_256(one, 256, all_one_out_256);
  TestCase all_one_512(one, 512, all_one_out_512);
  TestCase all_one_1024(one, 1024, all_one_out_1024);

  // This is the actual runner -- just in one place to make life easier.
  auto test_code = [&](const TestCase &test_case) {
    // Known answer test portion.
    EmpBlockOwningSpan input(test_case.input.size());
    std::copy(test_case.input.cbegin(), test_case.input.cend(), input.begin());
    CircuitSynthesis::hmac(key, input, output1);
    const auto out_str = print_hash_to_string(output1);
    CHECK(memcmp(out_str.data(), test_case.hash_out, 32) == 0);

    // Duplication test portion.
    CircuitSynthesis::hmac(key, input, output2);
    CHECK(emp::cmpBlock(output1, output2, 256));
  };

  SUBCASE("check that HMAC is deterministic on all 0s") {
    test_code(all_zeroes);
  }

  SUBCASE("check that HMAC is determininstic on all 1s (256)") {
    test_code(all_one_256);
  }

  SUBCASE("check that MAC is deterministic on all 1s (512)") {
    test_code(all_one_512);
  }

  SUBCASE("check that HMAC is deterministic on all 1s (1024)") {
    test_code(all_one_1024);
  }

  emp::finalize_plain_prot();
}

TEST_CASE("hkdf_extract") {
  emp::setup_plain_prot(false, "test_hkdf.txt");
  emp::block output[256];

  EmpBlockOwningSpan key(256);
  EmpBlockOwningSpan salt(8);

  const auto zero = emp::CircuitExecution::circ_exec->public_label(false);
  std::fill(key.begin(), key.end(), zero);
  std::fill(salt.begin(), salt.end(), zero);

  // This also comes from n-for-1-auth
  static constexpr unsigned char extract_out[]{
      0x33, 0xAD, 0x0A, 0x1C, 0x60, 0x7E, 0xC0, 0x3B, 0x09, 0xE6, 0xCD,
      0x98, 0x93, 0x68, 0x0C, 0xE2, 0x10, 0xAD, 0xF3, 0x00, 0xAA, 0x1F,
      0x26, 0x60, 0xE1, 0xB2, 0x2E, 0x10, 0xF1, 0x70, 0xF9, 0x2A};

  CircuitSynthesis::hkdf_extract(salt, key, output);
  const auto as_arr = print_hash_to_string(output);
  CHECK(memcmp(as_arr.data(), extract_out, 32) == 0);
  emp::finalize_plain_prot();
}

TEST_CASE("hkdf_extract_boringssl") {
  // Test that HKDF extract works against an arbitrary
  // value produced by BoringSSL.
  constexpr auto repeats = 100;

  constexpr auto key_size = 256;
  constexpr auto salt_size = 16;

  for (unsigned k = 0; k < repeats; k++) {
    emp::setup_plain_prot(false, "test_hkdf.txt");
    const auto one = emp::CircuitExecution::circ_exec->public_label(true);
    const auto zero = emp::CircuitExecution::circ_exec->public_label(false);

    EmpBlockOwningSpan key(key_size);
    EmpBlockOwningSpan salt(salt_size);
    std::fill(std::begin(key), std::end(key), zero);
    std::fill(std::begin(salt), std::end(salt), zero);

    emp::block output[256];
    std::array<unsigned char, key_size / 8> bkey{};
    std::array<unsigned char, salt_size / 8> bsalt{};

    // Generate a random key and hash.
    for (auto &v : bsalt) {
      v = static_cast<unsigned char>(rand());
    }

    for (auto &v : bkey) {
      v = static_cast<unsigned char>(rand());
    }

    unsigned char w;
    for (unsigned i = 0; i < salt_size / 8; i++) {
      w = bsalt[i];
      for (unsigned j = 0; j < 8; j++) {
        salt[8 * i + j] = w & 1 ? one : zero;
        w >>= 1;
      }
    }

    for (unsigned i = 0; i < key_size / 8; i++) {
      w = bkey[i];
      for (unsigned j = 0; j < 8; j++) {
        key[8 * i + j] = w & 1 ? one : zero;
        w >>= 1;
      }
    }

    CircuitSynthesis::hkdf_extract(salt, key, output);
    const auto as_arr = print_hash_to_string(output);

    std::array<unsigned char, 32> output_hash{};

    size_t len;
    const auto *md = EVP_sha256();
    REQUIRE(HKDF_extract(output_hash.data(), &len, md, bkey.data(), bkey.size(),
                         bsalt.data(), bsalt.size()));

    CHECK(memcmp(output_hash.data(), as_arr.data(), sizeof(output_hash)) == 0);
    emp::finalize_plain_prot();
  }
}

TEST_CASE("hkdf_extract_label") {
  emp::setup_plain_prot(false, "test_extract_label.txt");
  const emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);
  EmpBlockOwningSpan early_secret(256);
  EmpBlockOwningSpan key(256);
  std::fill(key.begin(), key.end(), zero);
  EmpBlockOwningSpan salt(8);
  std::fill(salt.begin(), salt.end(), zero);

  constexpr static unsigned char derived_secret_out[]{
      0x6F, 0x26, 0x15, 0xA1, 0x08, 0xC7, 0x02, 0xC5, 0x67, 0x8F, 0x54,
      0xFC, 0x9D, 0xBA, 0xB6, 0x97, 0x16, 0xC0, 0x76, 0x18, 0x9C, 0x48,
      0x25, 0x0C, 0xEB, 0xEA, 0xC3, 0x57, 0x6C, 0x36, 0x11, 0xBA};

  CircuitSynthesis::hkdf_extract(salt, key, early_secret.data());
  print_hash_to_string(early_secret.data());
  EmpBlockOwningSpan empty_hash(0);
  EmpBlockOwningSpan empty_out(256);
  std::fill(empty_hash.begin(), empty_hash.end(), zero);
  CircuitSynthesis::sha256(empty_hash, empty_out.data());
  print_hash_to_string(empty_out.data());

  // Note: this test case is the same as computing the dES in TLS1.3
  // See https://eprint.iacr.org/2020/1044.pdf, Figure 1
  EmpBlockOwningSpan derived_secret(256);
  CircuitSynthesis::hkdf_expand_label(early_secret, "derived", empty_out,
                                      derived_secret.data(), 32);

  const auto as_arr = print_hash_to_string(derived_secret.data());
  CHECK(memcmp(as_arr.data(), derived_secret_out, 32) == 0);
  emp::finalize_plain_prot();
}

// This is just a helper function for generating random primes
static int generate_n_bit_prime(BIGNUM *prim, int bits, int safe) {
  return BN_generate_prime_ex(prim, bits, safe, nullptr, nullptr, nullptr);
}

//! [CircuitSynthesisBA2ES]
TEST_CASE("convert_bssl_array_to_emp_span") {
  emp::setup_plain_prot(false, "test_convert.txt");
  // We just create a random value and check that the bit pattern is as we
  // expect.
  static constexpr unsigned prime_lengths[]{256, 384, 512};
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  // These will hold the random prime and the random bignum respectively.
  auto *p = BN_CTX_get(bn_ctx.get());
  auto *rand = BN_CTX_get(bn_ctx.get());
  bssl::Array<uint8_t> serialised;

  REQUIRE(p);
  REQUIRE(rand);

  for (const auto prime_length : prime_lengths) {
    // We'll set up our numbers.
    REQUIRE(serialised.Init(prime_length / CHAR_BIT));
    REQUIRE(generate_n_bit_prime(p, static_cast<int>(prime_length), 0));
    REQUIRE(BN_rand_range_ex(rand, 1, p));
    // N.B The padded length here is in bytes, not bits.
    REQUIRE(BN_bn2bin_padded(serialised.data(), prime_length / CHAR_BIT, rand));

    // Convert into blocks.
    auto span = CircuitSynthesis::convert_bssl_array_to_emp_span(serialised);
    // We expect there to be a block for each bit.
    CHECK(span.size() == prime_length);

    const auto one = emp::CircuitExecution::circ_exec->public_label(true);
    const auto zero = emp::CircuitExecution::circ_exec->public_label(false);

    // Now we'll just iterate over and make sure all works.
    // N.B for neatness here we'll reverse the span's output.
    std::reverse(span.begin(), span.end());
    for (unsigned i = 0; i < prime_length / CHAR_BIT; i++) {
      auto curr = serialised[i];
      for (unsigned j = 0; j < CHAR_BIT; j++) {
        if (curr & 1) {
          CHECK(emp::cmpBlock(&span[i * CHAR_BIT + j], &one, 1));
        } else {
          CHECK(emp::cmpBlock(&span[i * CHAR_BIT + j], &zero, 1));
        }
        curr >>= 1;
      }
    }
  }
  emp::finalize_plain_prot();
}
//! [CircuitSynthesisBA2ES]

static void bool_to_bn(BIGNUM *bn, bool *arr, const unsigned size) {
  BN_zero(bn);
  for (unsigned i = 0; i < size; i++) {
    if (arr[i]) {
      BN_set_bit(bn, static_cast<int>(i));
    }
  }
}

// Contains the primes under 50
// This choice was arbitrary, but as you increase the number of primes the
// cost increases a fair bit (as each prime has p^2 potential combinations)
static constexpr unsigned primes[] = {2,  3,  5,  7,  11, 13, 17, 19,
                                      23, 29, 31, 37, 41, 43, 47};

static constexpr uint64_t nr_entries() {
  // Each prime p has p^2 many ways of testing it
  // (There's p numbers including 0 less than p).
  // We'll calculate what that means in total.
  uint64_t total = 0;
  for (auto prime : primes) {
    total += prime * prime;
  }
  return total;
}

// This struct contains small inputs for our modulo addition testing.
// Note; the size of this could be reduced by 1/3rd by removing the prime
// as the third member. We could also generate each combination at runtime,
// but this would likely be expensive.
struct SmallInput {
  BN_ULONG a;
  BN_ULONG b;
  BN_ULONG p;
};

static constexpr std::array<SmallInput, nr_entries()>
produce_test_primes() noexcept {
  std::array<SmallInput, nr_entries()> test_inputs{};
  unsigned curr_entry = 0;
  for (auto prime : primes) {
    for (unsigned i = 0; i < prime; i++) {
      for (unsigned j = 0; j < prime; j++) {
        test_inputs[curr_entry] = {i, j, prime};
        curr_entry++;
      }
    }
  }
  return test_inputs;
}

// `inputs` contains all pairs of entries for each prime in `primes`
// In particular, for a given prime `p` we store (0, ..., p-1) X (0, ...,
// p-1), where X is the Cartesian product. We build this array at runtime.
static constexpr auto inputs = produce_test_primes();

// This template class is just a wrapper to make passing things around
// slightly neater.
template <unsigned prime_length> struct BoolRep {
  std::array<bool, prime_length> a;
  std::array<bool, prime_length> b;
  std::array<bool, prime_length> p;
};

template <int prime_length>
static void
transcribe_bns_to_bool(BoolRep<static_cast<unsigned>(prime_length)> &as_bools,
                       const BIGNUM *const a, const BIGNUM *const b,
                       const BIGNUM *const p) noexcept {

  REQUIRE(a);
  REQUIRE(b);
  REQUIRE(p);

  for (int i = 0; i < prime_length; i++) {
    // Note: BoringSSL wants int arguments, C++ wants unsigned arguments.
    // So we cast.
    const auto j = static_cast<unsigned>(i);
    as_bools.a[j] = BN_is_bit_set(a, i);
    as_bools.b[j] = BN_is_bit_set(b, i);
    as_bools.p[j] = BN_is_bit_set(p, i);
  }
}

// This helper function computes a + b (mod p) and checks that the results
// are the same as we'd expect from BoringSSL.
template <int prime_length>
static void add_func(const BIGNUM *const a, const BIGNUM *const b,
                     const BIGNUM *const p, BIGNUM *const sum,
                     BIGNUM *const out_bn, emp::block *const out,
                     BoolRep<static_cast<unsigned>(prime_length)> &as_bools,
                     BN_CTX *const ctx) noexcept {

  // Test code needs tests too.
  REQUIRE(a);
  REQUIRE(b);
  REQUIRE(p);
  REQUIRE(sum);
  REQUIRE(out_bn);
  REQUIRE(out);
  REQUIRE(ctx);

  // Now we'll transcribe each bignum into a little endian boolean
  // representation.
  transcribe_bns_to_bool<prime_length>(as_bools, a, b, p);
  // Call the circuit.
  CircuitSynthesis::add_two_mod_p(&as_bools.a[0], &as_bools.b[0],
                                  &as_bools.p[0], out, prime_length);

  // We'll now reveal the entries in `out` (this is just for testing).
  bool out_bool[static_cast<unsigned>(prime_length)];
  emp::ProtocolExecution::prot_exec->reveal(out_bool, emp::PUBLIC, out,
                                            prime_length);

  // And now turn it into a bignum.
  bool_to_bn(out_bn, out_bool, prime_length);
  REQUIRE(BN_mod_add(sum, a, b, p, ctx));
  CHECK(BN_cmp(out_bn, sum) == 0);
}
// This helper function tests that computing a + b (mod p) works for small
// inputs. Note that this relies upon a, b < p.
template <int prime_length>
static void
small_value_test(const SmallInput test_case, BIGNUM *const a, BIGNUM *const b,
                 BIGNUM *const p, BIGNUM *const sum, BIGNUM *const out_bn,
                 emp::block *const output,
                 BoolRep<static_cast<unsigned>(prime_length)> &as_bools,
                 BN_CTX *const ctx) noexcept {

  // Test code needs tests too
  REQUIRE(a);
  REQUIRE(b);
  REQUIRE(p);
  REQUIRE(sum);
  REQUIRE(out_bn);
  REQUIRE(ctx);

  // We have to transcribe each entry into a boolean representation.
  REQUIRE(BN_set_word(a, test_case.a));
  REQUIRE(BN_set_word(b, test_case.b));
  REQUIRE(BN_set_word(p, test_case.p));
  // And then add_func will do the rest.
  add_func<prime_length>(a, b, p, sum, out_bn, output, as_bools, ctx);
}

// This helper function tests that computing a + b (mod p) works for random
// values. Note that this relies upon a, b < p.
template <int prime_length>
static void
large_value_test(BIGNUM *const a, BIGNUM *const b, BIGNUM *const p,
                 BIGNUM *const sum, BIGNUM *const out_bn,
                 emp::block *const output,
                 BoolRep<static_cast<unsigned>(prime_length)> &as_bools,
                 BN_CTX *const ctx) noexcept {

  // Test code needs tests too
  REQUIRE(a);
  REQUIRE(b);
  REQUIRE(p);
  REQUIRE(sum);
  REQUIRE(out_bn);
  REQUIRE(output);
  REQUIRE(ctx);

  // Firstly we generate a random prime to put in `p`.
  // The last parameter means generate a safe prime.
  REQUIRE(generate_n_bit_prime(p, prime_length, 1));

  // Now we'll generate two numbers `a`, `b` < p.
  REQUIRE(BN_rand_range_ex(a, 1, p));
  REQUIRE(BN_rand_range_ex(b, 1, p));

  // Now we'll call the addition routine.
  add_func<prime_length>(a, b, p, sum, out_bn, output, as_bools, ctx);
}

// Doctest doesn't support templated test cases for non-type arguments.
// To fix that, we make each prime its own type (this is an old C++
// metaprogramming trick).
template <unsigned length> struct PrimeSize {
  static constexpr unsigned value = length;
};

// N.B this is in a test suite to make it easier to call from the command
// line. Essentially, wrapping everything in a templated test case makes it a
// little bit harder to call. To call this exclusively (i.e just the
// add_two_mod_p tests) invoke the test executable with
// --test-suite=add_two_mod_p For example:
// ./CircuitSynthesisDebugTests --test-suite=add_two_mod_p

//! [CircuitSynthesisAddTwoModP]
TEST_SUITE_BEGIN("add_two_mod_p");
// This is a single test case for all prime lengths we care about.
TEST_CASE_TEMPLATE("add_two_mod_p", prime, PrimeSize<256>, PrimeSize<384>,
                   PrimeSize<521>) {
  emp::setup_plain_prot(false, "test_add.txt");
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  // Here we use `p` as our modulus and `a`, `b` as inputs.
  BIGNUM *p = BN_CTX_get(bn_ctx.get());
  BIGNUM *a = BN_CTX_get(bn_ctx.get());
  BIGNUM *b = BN_CTX_get(bn_ctx.get());
  // This contains the BoringSSL sum as a bignum.
  BIGNUM *sum = BN_CTX_get(bn_ctx.get());
  // This contains the CircuitSynthesis sum as a bignum.
  BIGNUM *out_bn = BN_CTX_get(bn_ctx.get());

  // Allocations should work.
  REQUIRE(p);
  REQUIRE(a);
  REQUIRE(b);
  REQUIRE(sum);
  REQUIRE(out_bn);

  // Fetch out our prime size from the type.
  static constexpr auto prime_length = prime::value;

  // Now we'll check small values work.
  // To make the helper functions easier to use, we provide a singular
  // wrapper that holds the bitwise representations of each bignum.
  BoolRep<prime_length> bools;

  // We'll write all outputs into this array.
  emp::block output[prime_length];

  SUBCASE("Small values") {
    for (const auto test_case : inputs) {
      small_value_test<prime_length>(test_case, a, b, p, sum, out_bn, output,
                                     bools, bn_ctx.get());
    }
  }

  SUBCASE("Large values") {
    // We'll repeat this some number of times. Runtimes vary with this
    // parameter.
    static constexpr auto repeats = 10;
    for (unsigned i = 0; i < repeats; i++) {
      large_value_test<prime_length>(a, b, p, sum, out_bn, output, bools,
                                     bn_ctx.get());
    }
  }

  emp::finalize_plain_prot();
}
TEST_SUITE_END();
//! [CircuitSynthesisAddTwoModP]

TEST_CASE("rearrange_sum_bits") {
  static constexpr auto size = 512;
  static_assert(size % 8 == 0);
  EmpBlockOwningSpan data(size);
  Util::generate_random_bytes<sizeof(emp::block) * size>(data.data());
  EmpBlockOwningSpan copy(data);

  CircuitSynthesis::rearrange_sum_bits(data);

  const auto width = size / 8;
  for (unsigned i = 0; i < width; i++) {
    std::reverse(std::begin(copy) + i * 8, std::begin(copy) + (i + 1) * 8);
  }

  std::reverse(std::begin(copy), std::end(copy));

  CHECK(emp::cmpBlock(data.data(), copy.data(), size));
}

template <bool expand> static void test_output(const unsigned size) {
  // This function tests that the output of feeding the summation
  // into the hmac_extract function does "what we'd expect it to do" (i.e
  // outputs the same as BoringSSL on the same inputs). Because BoringSSL has a
  // different endianness scheme to our circuits, this function is a little bit
  // technical in places. We'll highlight that when it comes up.
  emp::setup_plain_prot(false, "test_add.txt");
  const emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);
  const emp::block one = emp::CircuitExecution::circ_exec->public_label(true);

  // We'll need this for allocating bignums.
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  // This is primarily to make sure that the size can be neatly recombined (see
  // more later).
  REQUIRE(size % 8 == 0);

  // We only support 512 bits at most.
  REQUIRE(size <= 512);

  // Get the random prime and the two arbitrary inputs. We'll compute
  // a + b mod p inside the garbled circuit.
  auto get_bignum = [&]() {
    auto out = BN_CTX_get(bn_ctx.get());
    REQUIRE(out);
    return out;
  };

  auto *p = get_bignum();
  auto *a = get_bignum();
  auto *b = get_bignum();

  REQUIRE(generate_n_bit_prime(p, static_cast<int>(size), 1));
  REQUIRE(BN_rand_range_ex(a, 1, p));
  REQUIRE(BN_rand_range_ex(b, 1, p));

  // Now we'll serialise each produced bignum. We use an array of bools
  // because of std::vector<bool> weirdness.
  std::array<bool, 512> a_bits{}, b_bits{}, p_bits{};

  for (unsigned i = 0; i < size; i++) {
    const auto j = static_cast<int>(i);
    a_bits[i] = BN_is_bit_set(a, j);
    b_bits[i] = BN_is_bit_set(b, j);
    p_bits[i] = BN_is_bit_set(p, j);
  }

  // And finally add everything up.
  EmpBlockOwningSpan output_sum(size);
  REQUIRE(output_sum.data());

  CircuitSynthesis::add_two_mod_p(a_bits.data(), b_bits.data(), p_bits.data(),
                                  output_sum.data(), size);

  // NOW COMES THE WEIRD BIT.
  // Our circuits output a little endian sequence of numbers that are
  // _backwards_ relative to the input that is expected by our HKDF circuits
  // (i.e they might expect 0,1,2,3,4,5,6,7 but our circuits output
  // 7,6,5,4,3,2,1,0). We thus reverse each individual bit sequence and then
  // reverse the entire endianness of the entire thing. This does not cost
  // anything inside emp, as we're just shuffling wires.
  CircuitSynthesis::rearrange_sum_bits(output_sum);
  // END OF THE WEIRD BIT.

  // Now we compute the result of HKDF.Extract. We'll allocate the space
  // first and then deserialise the (fixed across calls) dES value.
  EmpBlockOwningSpan derived_secret(size);
  REQUIRE(derived_secret.data());
  constexpr std::array<uint8_t, 32> dES{
      0x6F, 0x26, 0x15, 0xA1, 0x08, 0xC7, 0x02, 0xC5, 0x67, 0x8F, 0x54,
      0xFC, 0x9D, 0xBA, 0xB6, 0x97, 0x16, 0xC0, 0x76, 0x18, 0x9C, 0x48,
      0x25, 0x0C, 0xEB, 0xEA, 0xC3, 0x57, 0x6C, 0x36, 0x11, 0xBA};

  emp::block context[256];
  for (unsigned i = 0; i < 32; i++) {
    unsigned char w = dES[i];
    for (unsigned j = 0; j < 8; j++) {
      context[8 * i + j] = w & 1 ? one : zero;
      w >>= 1;
    }
  }

  // derived_secret = HKDF.Extract(DHE, dES), with DHE = output and
  // dES = context. NOTE: the size does not need to be padded here as the
  // sizes are already correct. Note that the context is always 256 in size.
  static_assert(dES.size() == 32);
  CircuitSynthesis::hkdf_extract(EmpBlockNonOwningSpan{context, 256},
                                 EmpBlockNonOwningSpan{output_sum.data(), size},
                                 derived_secret.data());

  // Only output the expanded version if we've asked for it.

  if (expand) {
    emp::block run_hash[256];
    std::fill(std::begin(run_hash), std::end(run_hash), zero);
    emp::block tmp_out[256];
    CircuitSynthesis::hkdf_expand_label(
        EmpBlockNonOwningSpan{derived_secret.data(), 256}, "c hs traffic",
        EmpBlockNonOwningSpan{run_hash, 256}, tmp_out, 32);
    memcpy(derived_secret.data(), tmp_out, sizeof(tmp_out));
  }

  // And now we get the result of the hash. This function does some
  // re-arrangement of the bits in derived_secret too. Again, this doesn't cost
  // anything.
  const auto emp_str = print_hash_to_string(derived_secret.data());

  // BoringSSL's bit. We first add a and  b (mod p), serialise
  // the result and then call HKDF.Extract on that result.
  const auto *md = EVP_sha256();
  auto *res = BN_CTX_get(bn_ctx.get());
  REQUIRE(res);
  REQUIRE(md);
  REQUIRE(BN_mod_add(res, a, b, p, bn_ctx.get()));
  bssl::Array<uint8_t> arr;
  const auto width = size / 8;
  REQUIRE(arr.Init(width));
  REQUIRE(BN_bn2bin_padded(arr.data(), arr.size(), res));

  // The output is always 256 bits. Note that the
  // BoringSSL output is already in the right order.
  std::array<unsigned char, 32> output_hash{};
  size_t len;
  REQUIRE(HKDF_extract(output_hash.data(), &len, md, arr.data(), arr.size(),
                       dES.data(), dES.size()));

  if (expand) {
    // If we're expanding then we also need to feed that output secret
    // into the expand_label code.
    const std::string protocol_label = "tls13 ";
    const std::string label = "c hs traffic";
    bssl::ScopedCBB cbb;
    CBB child;
    std::array<unsigned char, 32> tmp_hash;
    std::fill(tmp_hash.begin(), tmp_hash.end(), 0);

    bssl::Array<uint8_t> hkdf_label;
    if (!CBB_init(cbb.get(),
                  2 + 1 + label.size() + protocol_label.size() + 1 + 32) ||
        !CBB_add_u16(cbb.get(), 32) ||
        !CBB_add_u8_length_prefixed(cbb.get(), &child) ||
        !CBB_add_bytes(&child,
                       reinterpret_cast<const uint8_t *>(protocol_label.data()),
                       protocol_label.size()) ||
        !CBB_add_bytes(&child, reinterpret_cast<const uint8_t *>(label.data()),
                       label.size()) ||
        !CBB_add_u8_length_prefixed(cbb.get(), &child) ||
        !CBB_add_bytes(&child, tmp_hash.data(), tmp_hash.size()) ||
        !CBBFinishArray(cbb.get(), &hkdf_label)) {
      REQUIRE(false);
    }

    std::array<unsigned char, 32> tmp_hash_out;
    REQUIRE(HKDF_expand(tmp_hash_out.data(), tmp_hash_out.size(), md,
                        output_hash.data(), output_hash.size(),
                        hkdf_label.data(), hkdf_label.size()));

    memcpy(output_hash.data(), tmp_hash_out.data(), tmp_hash_out.size());
  }

  // The outputs should all be the right size.
  REQUIRE(len == output_hash.size());
  REQUIRE(output_hash.size() == emp_str.size());

  // Finally check that the bits are the right size.
  CHECK(memcmp(output_hash.data(), emp_str.data(), sizeof(emp_str)) == 0);

  emp::finalize_plain_prot();
}

//! [CircuitSynthesisTestOutput]
TEST_CASE("test_extract_output") {
  // This function checks that addition and then feeding into
  // the HKDF extract works the same way as we'd expect.
  // For more detailed functions see "test_output".
  constexpr auto repeats = 5;

  SUBCASE("extract") {
    for (unsigned i = 0; i < repeats; i++) {
      test_output<false>(256);
      test_output<false>(384);
    }
  }

  SUBCASE("expand_label") {
    for (unsigned i = 0; i < repeats; i++) {
      test_output<true>(256);
      test_output<true>(384);
    }
  }
}
//! [CircuitSynthesisTestOutput]

template <unsigned size>
static constexpr std::array<bool, 8 * size>
chars_to_bools(const unsigned char *const arr) noexcept {
  // This function turns an input pointer into a sequence of
  // bools. Each bit in the input char array maps to a single bool
  // in the output array.
  // Note: arr must point to an array of at least `size` unsigned
  // chars, else the result is undefined.
  std::array<bool, 8 * size> out;
  for (unsigned i = 0; i < size; i++) {
    unsigned char w = arr[i];
    for (unsigned j = 0; j < 8; j++) {
      out[i * 8 + j] = w & 1;
      w >>= 1;
    }
  }

  return out;
}

//! [CircuitSynthesisTestKeys]
TEST_CASE("test_keys") {
  // Check that a derived hdkf key works as expected.
  static constexpr std::array<uint8_t, 32> test_data{
      0xa0, 0xac, 0x2e, 0x6b, 0xc7, 0x59, 0x4d, 0x13, 0xb1, 0x08, 0xa0,
      0x13, 0x5c, 0x1e, 0x51, 0x73, 0x93, 0x33, 0x02, 0x25, 0x07, 0x39,
      0x7e, 0x8a, 0xd7, 0x35, 0x62, 0x5c, 0xdd, 0x64, 0x73, 0x65};

  static constexpr std::array<uint8_t, 16> test_out{
      0xa1, 0x63, 0x56, 0xc5, 0x41, 0x7a, 0x9e, 0x58,
      0xf0, 0xa3, 0x2f, 0x68, 0x0f, 0x56, 0x8e, 0x75};

  const auto input = chars_to_bools<32>(test_data.data());

  emp::setup_plain_prot(false, "derive_keys.txt");
  emp::block secret[256];
  emp::ProtocolExecution::prot_exec->feed(secret, emp::PUBLIC, input.data(),
                                          256);

  emp::block *empty = nullptr;
  emp::block cts[128];
  CircuitSynthesis::hkdf_expand_label(EmpBlockNonOwningSpan{secret, 256}, "key",
                                      EmpBlockNonOwningSpan{empty, 0}, cts, 16);

  const auto res = print_hash_to_string<16>(cts);
  CHECK(res == test_out);
  emp::finalize_plain_prot();
}
//![CircuitSynthesisTestKeys]

static void setup_vals(std::array<uint32_t, 4> &vals,
                       EmpBlockArray<128> &a) noexcept {
  const emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);
  const emp::block one = emp::CircuitExecution::circ_exec->public_label(true);

  for (unsigned i = 0; i < 4; i++) {
    vals[i] = static_cast<uint32_t>(rand());
    auto copy = vals[i];
    for (unsigned j = 0; j < 32; j++) {
      a[i * 32 + j] = (copy & 1) ? one : zero;
      copy >>= 1;
    }
  }
}

//! [CircuitSynthesisTestShuffleEpi32]
TEST_CASE("test_shuffle_epi32") {
  std::array<uint32_t, 4> values;
  EmpBlockArray<128> a;

  for (unsigned i = 0; i < 256; i++) {
    emp::setup_plain_prot(false, "test_shuffle_epi32");
    setup_vals(values, a);
    const auto imm = uint8_t(i);
    const auto result = CircuitSynthesis::shuffle_epi32(a, imm);
    const auto as_str = print_hash_to_string<16>(result.data());

    // Now check the bits.
    const auto first = imm & 3;
    const auto second = (imm >> 2) & 3;
    const auto third = (imm >> 4) & 3;
    const auto fourth = (imm >> 6) & 3;

    REQUIRE(memcmp(as_str.data(), values.data() + first,
                   sizeof(values[first])) == 0);
    REQUIRE(memcmp(as_str.data() + 4, values.data() + second,
                   sizeof(values[second])) == 0);
    REQUIRE(memcmp(as_str.data() + 8, values.data() + third,
                   sizeof(values[third])) == 0);
    REQUIRE(memcmp(as_str.data() + 12, values.data() + fourth,
                   sizeof(values[fourth])) == 0);

    emp::finalize_plain_prot();
  }
}
//! [CircuitSynthesisTestShuffleEpi32]

//! [CircuitSynthesisTestXorSi128]
TEST_CASE("test_xor_si128") {
  emp::setup_plain_prot(false, "test_xorsi128");
  EmpBlockArray<128> a, b;

  const emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);
  const emp::block one = emp::CircuitExecution::circ_exec->public_label(true);
  std::fill(a.begin(), a.end(), zero);
  std::fill(b.begin(), b.end(), zero);

  SUBCASE("both zero") {
    const auto out =
        print_hash_to_string<16>(CircuitSynthesis::xor_si128(a, b).data());
    constexpr std::array<uint8_t, 16> all_zeroes{};
    CHECK(memcmp(all_zeroes.data(), out.data(), sizeof(all_zeroes)) == 0);
  }

  SUBCASE("a[0] is one") {
    a[0] = one;
    const auto out =
        print_hash_to_string<16>(CircuitSynthesis::xor_si128(a, b).data());
    std::array<uint8_t, 16> expected{};
    expected[0] = 1;
    CHECK(memcmp(expected.data(), out.data(), sizeof(expected)) == 0);
  }

  SUBCASE("b[0] is one") {
    b[0] = one;
    const auto out =
        print_hash_to_string<16>(CircuitSynthesis::xor_si128(a, b).data());
    std::array<uint8_t, 16> expected{};
    expected[0] = 1;
    CHECK(memcmp(expected.data(), out.data(), sizeof(expected)) == 0);
  }

  SUBCASE("a[0] == b[0] == 1") {
    a[0] = b[0] = one;
    const auto out =
        print_hash_to_string<16>(CircuitSynthesis::xor_si128(a, b).data());
    constexpr std::array<uint8_t, 16> expected{};
    CHECK(memcmp(expected.data(), out.data(), sizeof(expected)) == 0);
  }

  emp::finalize_plain_prot();
}
//! [CircuitSynthesisTestXorSi128]

//! [CircuitSynthesisTestSllisi128]
TEST_CASE("test_slli_si128") {
  std::array<uint32_t, 4> values;
  EmpBlockArray<128> a;

  for (unsigned i = 0; i < 16; i++) {
    emp::setup_plain_prot(false, "test_slli_si128");
    const emp::block zero =
        emp::CircuitExecution::circ_exec->public_label(false);
    setup_vals(values, a);
    const auto imm = uint8_t(i);
    const auto result = CircuitSynthesis::slli_si128(a, imm);

    // slli_si128 shifts `a` to the left by `imm` bytes.
    // Since Intel assumes that CHAR_BIT == 8, this means we expect the
    // following.
    // 1. The elements between a -> a + (imm*8) are in the range [result.begin()
    // + imm*8, result.end())
    CHECK(emp::cmpBlock(&a[0], &result[imm * 8], 128 - (imm * 8)));

    // 2. The elements in [result.begin(), result.begin() + imm*8) are all zero.
    for (unsigned j = 0; j < imm * 8; j++) {
      CHECK(emp::cmpBlock(&result[j], &zero, 1));
    }

    emp::finalize_plain_prot();
  }
}
//! [CircuitSynthesisTestsSllisi128]

//! [CircuitSynthesisTestsSrlisi128]
TEST_CASE("test_srli_si128") {
  std::array<uint32_t, 4> values;
  EmpBlockArray<128> a;

  for (unsigned i = 0; i < 16; i++) {
    emp::setup_plain_prot(false, "test_srli_si128");
    const emp::block zero =
        emp::CircuitExecution::circ_exec->public_label(false);
    setup_vals(values, a);
    const auto imm = uint8_t(i);
    const auto result = CircuitSynthesis::srli_si128(a, imm);

    // srli_si128 shifts `a` to the right by `imm` bytes.
    // Since Intel assumes that CHAR_BIT == 8, this means we expect the
    // following.
    // 1. The elements of [a+(imm*8), a.end()) are in the range [result.begin(),
    // result + (128 - (imm*8))).
    REQUIRE(emp::cmpBlock(&a[imm * 8], &result[0], (128 - (imm * 8))));

    // 2. The top (imm * 8) elements are all zero.
    for (unsigned j = 0; j < imm * 8; j++) {
      REQUIRE(emp::cmpBlock(&result[127 - j], &zero, 1));
    }

    emp::finalize_plain_prot();
  }
}
//! [CircuitSynthesisTestsSllisi128]

//! [CircuitSynthesisTestSlliEpi32]
TEST_CASE("test_slli_epi32") {
  std::array<uint32_t, 4> values;
  EmpBlockArray<128> a;

  for (unsigned i = 0; i < 32; i++) {
    emp::setup_plain_prot(false, "test_slli_epi32");
    const emp::block zero =
        emp::CircuitExecution::circ_exec->public_label(false);
    setup_vals(values, a);
    const auto imm = uint8_t(i);
    const auto result = CircuitSynthesis::slli_epi32(a, imm);

    // slli_epi32 shifts each 32 bit word individually.
    // So, we expect the following:
    // 1. The first imm bits of each 32 bit word should be all zero.
    for (unsigned j = 0; j < 4; j++) {
      for (unsigned k = 0; k < imm; k++) {
        CHECK(emp::cmpBlock(&result[j * 32 + k], &zero, 1));
      }
    }

    // 2. The remaining 32 - imm bits should be the same as those at the start
    // of each original 32 bit word.
    for (unsigned j = 0; j < 4; j++) {
      CHECK(emp::cmpBlock(&result[j * 32 + imm], &a[j * 32], (32 - imm)));
    }
    emp::finalize_plain_prot();
  }
}
//! [CircuitSynthesisTestSlliEpi32]

//! [CircuitSynthesisTestSrliEpi32]
TEST_CASE("test_srli_epi32") {
  std::array<uint32_t, 4> values;
  EmpBlockArray<128> a;

  for (unsigned i = 0; i < 32; i++) {
    emp::setup_plain_prot(false, "test_srli_epi32");
    const emp::block zero =
        emp::CircuitExecution::circ_exec->public_label(false);
    setup_vals(values, a);
    const auto imm = uint8_t(i);
    const auto result = CircuitSynthesis::srli_epi32(a, imm);

    // srli_epi32 shifts each 32 bit word individually.
    // So, we expect the following:
    // 1. The first 32 - imm bits should be the same as the offset ones in a.
    for (unsigned j = 0; j < 4; j++) {
      REQUIRE(emp::cmpBlock(&result[j * 32], &a[j * 32 + imm], (32 - imm)));
    }

    // 2. The remaining imm bits (at the top of each word) should all be 0.
    for (unsigned j = 0; j < 4; j++) {
      for (unsigned k = 0; k < imm; k++) {
        REQUIRE(emp::cmpBlock(&result[(j + 1) * 32 - 1 - k], &zero, 1));
      }
    }
    emp::finalize_plain_prot();
  }
}
//! [CircuitSynthesisTestSrliEpi32]

//! [CircuitSynthesisTestAndSi128]
TEST_CASE("test_and_si128") {
  emp::setup_plain_prot(false, "test_andsi128");
  EmpBlockArray<128> a, b;

  const emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);
  const emp::block one = emp::CircuitExecution::circ_exec->public_label(true);
  std::fill(a.begin(), a.end(), zero);
  std::fill(b.begin(), b.end(), zero);

  SUBCASE("both zero") {
    const auto out =
        print_hash_to_string<16>(CircuitSynthesis::and_si128(a, b).data());
    constexpr std::array<uint8_t, 16> all_zeroes{};
    CHECK(memcmp(all_zeroes.data(), out.data(), sizeof(all_zeroes)) == 0);
  }

  SUBCASE("a[0] is one") {
    a[0] = one;
    const auto out =
        print_hash_to_string<16>(CircuitSynthesis::and_si128(a, b).data());
    constexpr std::array<uint8_t, 16> all_zeroes{};
    CHECK(memcmp(all_zeroes.data(), out.data(), sizeof(all_zeroes)) == 0);
  }

  SUBCASE("b[0] is one") {
    b[0] = one;
    const auto out =
        print_hash_to_string<16>(CircuitSynthesis::and_si128(a, b).data());
    constexpr std::array<uint8_t, 16> all_zeroes{};
    CHECK(memcmp(all_zeroes.data(), out.data(), sizeof(all_zeroes)) == 0);
  }

  SUBCASE("a[0] == b[0] == 1") {
    a[0] = b[0] = one;
    const auto out =
        print_hash_to_string<16>(CircuitSynthesis::and_si128(a, b).data());
    std::array<uint8_t, 16> expected{};
    expected[0] = 1;
    CHECK(memcmp(expected.data(), out.data(), sizeof(expected)) == 0);
  }

  emp::finalize_plain_prot();
}
//! [CircuitSynthesisTestAndSi128]

//! [CircuitSynthesisTestAndNotSi128]
TEST_CASE("test_and_not_si128") {
  emp::setup_plain_prot(false, "test_andnotsi128");
  EmpBlockArray<128> a, b;

  const emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);
  const emp::block one = emp::CircuitExecution::circ_exec->public_label(true);
  std::fill(a.begin(), a.end(), zero);
  std::fill(b.begin(), b.end(), zero);

  SUBCASE("both zero") {
    const auto out =
        print_hash_to_string<16>(CircuitSynthesis::andnot_si128(a, b).data());
    constexpr std::array<uint8_t, 16> all_zeroes{};
    CHECK(memcmp(all_zeroes.data(), out.data(), sizeof(all_zeroes)) == 0);
  }

  SUBCASE("a[0] is one") {
    a[0] = one;
    const auto out =
        print_hash_to_string<16>(CircuitSynthesis::andnot_si128(a, b).data());
    constexpr std::array<uint8_t, 16> all_zeroes{};
    CHECK(memcmp(all_zeroes.data(), out.data(), sizeof(all_zeroes)) == 0);
  }

  SUBCASE("b[0] is one") {
    b[0] = one;
    const auto out =
        print_hash_to_string<16>(CircuitSynthesis::andnot_si128(a, b).data());
    std::array<uint8_t, 16> expected{};
    expected[0] = 1;
    CHECK(memcmp(expected.data(), out.data(), sizeof(expected)) == 0);
  }

  SUBCASE("a[0] == b[0] == 1") {
    a[0] = b[0] = one;
    const auto out =
        print_hash_to_string<16>(CircuitSynthesis::andnot_si128(a, b).data());
    constexpr std::array<uint8_t, 16> all_zeroes{};
    CHECK(memcmp(all_zeroes.data(), out.data(), sizeof(all_zeroes)) == 0);
  }

  emp::finalize_plain_prot();
}
//! [CircuitSynthesisTestAndNotSi128]

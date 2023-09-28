/**
   This file contains the code for deriving the circuits used by this project.
It is not a test file and it should be considered as a separate entity from the
rest of the code.

Please note that the notation used in this file for various circuits etc comes
from https://eprint.iacr.org/2020/1044.pdf, in particular Figure 1.

This file is a little bit long, but it seems to actually be the best way to keep
the code separate from the rest of the code-base.

Understanding the code:

- This file is designed to be self-contained. Where appropriate, each function
has a "testable" version that lets you check that it works as we would expect
(compared to n-for-1 auth).

- This file deals a lot with sharing the output of a garbled circuit. We employ
3 distinct approaches for this:
  1. For 256-bit outputs, we give the lower 128-bits to Alice and the upper
128-bits to Bob. Each party must supply a unique 128 bit mask to prevent
leakage.
  2. For 128-bit outputs in the combined circuit, both Alice and Bob supply a
128-bit mask. Alice receives the keys produced (xored with the mask) whereas Bob
receives the IVs produced (xored with the mask).
  3. For 128-bit outputs, Bob must supply a unique 128-bit mask (m) to xor
against the produced output (o). Alice receives m \xor o and Bob receives
nothing. We do this because if we were to follow approach (1), either Alice or
Bob could attempt to brute-force the key after just a few messages -- it would
take around 2^64 operations, which isn't high-enough. This allows us to do
better: in fact, if Bob's mask is unique, this is equivalent to a OTP. This does
mean that all circuits that require 128-bit inputs must deal with removing this
mask -- in practice, this just requires Alice to provide m \xor o, and for Bob
to provide m, which can then be xored together. This only costs an additional
128 XOR gates, which are nominally expensive in a garbled circuit.
**/

#include "../Decl.hpp" // Needed for macros.
#include "../emp-ot/emp-ot/emp-ot.h"
#include "../mta/EmpBlockArray.hpp" // Needed for an array that respects attributes.
#include "../ssl/Util.hpp"          // Needed for various utilities.
#include "CircuitSynthesis.hpp"     // Needed for circuit synthesis.
// The first load of functions are essentially just utilities.

// This function takes a public output and returns an array of bytes.
// The way this function works is as follows: emp outputs each bit of
// its output into a separate block. Assuming that there are 8-bits in a byte,
// we can copy over each set of 8 blocks into our array, bit by bit.
// We assume that the output is little-endian, so we start on the lower
// element and shift along.
// NOTE: as a pre-condition we assume that output has at least 8 * nr_bytes
// entries. If this is not true, you will encounter undefined behaviour.
template <unsigned nr_bytes>
static std::array<unsigned char, nr_bytes>
print_hash_to_string(const emp::block *const output) {
  unsigned char digest_char[nr_bytes]{};

  // Just to make sure the hard-coding doesn't break anything.
  // N.B This may not actually be a problem because emp probably assumes
  // that CHAR_BIT == 8.
  static_assert(CHAR_BIT == 8, "Error: function expects CHAR_BIT == 8");

  bool output_bool[nr_bytes * 8];
  emp::ProtocolExecution::prot_exec->reveal(output_bool, emp::PUBLIC, output,
                                            nr_bytes * 8);

  for (unsigned i = 0; i < nr_bytes; i++) {
    unsigned char w = 1;
    for (unsigned j = 0; j < 8; j++) {
      digest_char[i] += static_cast<unsigned char>(
          w * static_cast<unsigned char>(output_bool[i * 8 + j]));
      w *= 2;
    }
  }

  std::array<unsigned char, nr_bytes> out;
  memcpy(out.data(), digest_char, nr_bytes);
  return out;
}

static std::array<unsigned char, 32> get_empty_hash() noexcept {
  static constexpr std::array<unsigned char, 32> empty_hash{
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
      0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
      0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

  return empty_hash;
}

template <unsigned int length> static EC_GROUP *get_curve() noexcept {
  // This function returns the group associated with the NIST curve with
  // bit-size `length`. This is used for modular arithmetic.
  static_assert(length == 256 || length == 384 || length == 521,
                "Error: mismatched size");

  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  assert(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  static constexpr auto curve_id = [&]() {
    if constexpr (length == 256) {
      return SSL_CURVE_SECP256R1;
    } else if constexpr (length == 384) {
      return SSL_CURVE_SECP384R1;
    } else {
      return SSL_CURVE_SECP521R1;
    }
  }();

  return EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve_id));
}

template <unsigned prime_length>
static std::array<bool, prime_length>
serialise_bignum(const BIGNUM *const num) noexcept {
  // This function serialises `num` into an array as a big endian number.
  // This is just used for generating circuits and will not be used in the
  // circuits themselves.
  assert(num);
  std::array<bool, prime_length> arr;
  for (unsigned i = 0; i < prime_length; i++) {
    arr[i] = BN_is_bit_set(num, static_cast<int>(i));
  }
  return arr;
}

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

template <unsigned size>
static constexpr EmpBlockArray<size * 8>
chars_to_blocks(const unsigned char *const arr) noexcept {
  // This function turns an input pointer of chars into a sequence of blocks.
  // Each bit in the input char array maps to a single block in the output
  // array. Note that emp::setup_plain_prot must have been called before a call
  // to this function.
  EmpBlockArray<size * 8> out{};
  const emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);
  const emp::block one = emp::CircuitExecution::circ_exec->public_label(true);

  for (unsigned i = 0; i < size; i++) {
    unsigned char w = arr[i];
    for (unsigned j = 0; j < 8; j++) {
      out[i * 8 + j] = w & 1 ? one : zero;
      w >>= 1;
    }
  }
  return out;
}

static void extract_secret_each(emp::block *const derived_secret,
                                bool *const alice_out_ptr = nullptr,
                                bool *const bob_out_ptr = nullptr) {

  bool alice_out_bool[128];
  bool bob_out_bool[128];
  emp::ProtocolExecution::prot_exec->reveal(alice_out_bool, emp::ALICE,
                                            derived_secret, 128);
  emp::ProtocolExecution::prot_exec->reveal(bob_out_bool, emp::BOB,
                                            derived_secret + 128, 128);

  // Write to the out parameters if supplied.
  if (alice_out_ptr) {
    memcpy(alice_out_ptr, alice_out_bool, sizeof(bool) * 128);
  }

  if (bob_out_ptr) {
    memcpy(bob_out_ptr, bob_out_bool, sizeof(bool) * 128);
  }
}

// This enum exists solely to specialise DeriveIVOrKey.
// In essense, this enum specifies which type of derivation we are doing:
// either IVs for the handshake, keys for the handshake, IVs for the record
// layer, keys for the record layer, or other secrets.
enum class TypeOfDerivation {
  CLIENT_HANDSHAKE_IV = 0,
  CLIENT_TRAFFIC_IV = 1,
  SERVER_HANDSHAKE_IV = 2,
  SERVER_TRAFFIC_IV = 3,
  CLIENT_HANDSHAKE_KEY = 4,
  CLIENT_TRAFFIC_KEY = 5,
  SERVER_HANDSHAKE_KEY = 6,
  SERVER_TRAFFIC_KEY = 7,
  DHS = 8,
  SERVER_HTS = 9,
  CLIENT_HTS = 10,
  MS = 11,
  CATS = 12,
  SATS = 13,
  EMS = 14,
  FK_S = 15,
  SIZE = 16
};

template <TypeOfDerivation mode>
static constexpr const char *get_tag() noexcept {
  // This function exists to return the right tag for calls into the
  // hkdf_expand_label function.
  static_assert(mode != TypeOfDerivation::SIZE, "mode cannot == SIZE");
  // We don't call tag for MS: this is because the master secret isn't
  // derived using a call to hkdf_expand_label.
  static_assert(mode != TypeOfDerivation::MS, "MS should not call get_tag");
  switch (mode) {
  case TypeOfDerivation::CLIENT_HANDSHAKE_IV:
  case TypeOfDerivation::CLIENT_TRAFFIC_IV:
  case TypeOfDerivation::SERVER_HANDSHAKE_IV:
  case TypeOfDerivation::SERVER_TRAFFIC_IV:
    return "iv";
  case TypeOfDerivation::DHS:
    return "derived";
  case TypeOfDerivation::CLIENT_HANDSHAKE_KEY:
  case TypeOfDerivation::CLIENT_TRAFFIC_KEY:
  case TypeOfDerivation::SERVER_HANDSHAKE_KEY:
  case TypeOfDerivation::SERVER_TRAFFIC_KEY:
    return "key";
  case TypeOfDerivation::SERVER_HTS:
    return "s hs traffic";
  case TypeOfDerivation::CLIENT_HTS:
    return "c hs traffic";
  case TypeOfDerivation::CATS:
    return "c ap traffic";
  case TypeOfDerivation::SATS:
    return "s ap traffic";
  case TypeOfDerivation::FK_S:
    return "finished";
  case TypeOfDerivation::EMS:
    return "exp master";
  }

  // The compiler should be able to deduce this, but you never know.
  COMPAT_UNREACHABLE();
}

template <TypeOfDerivation mode>
static constexpr const char *get_filename() noexcept {
  // This funciton exists solely to return the filename to be used for
  // derivation circuits. This is primarily to make DeriveIVOrKey neater.
  static_assert(mode != TypeOfDerivation::SIZE, "mode cannot == SIZE");
  switch (mode) {
  case TypeOfDerivation::CLIENT_HANDSHAKE_IV:
    return "derive_client_handshake_iv.txt";
  case TypeOfDerivation::CLIENT_TRAFFIC_IV:
    return "derive_client_traffic_iv.txt";
  case TypeOfDerivation::SERVER_HANDSHAKE_IV:
    return "derive_server_handshake_iv.txt";
  case TypeOfDerivation::SERVER_TRAFFIC_IV:
    return "derive_server_traffic_iv.txt";
  case TypeOfDerivation::CLIENT_HANDSHAKE_KEY:
    return "derive_client_handshake_key.txt";
  case TypeOfDerivation::CLIENT_TRAFFIC_KEY:
    return "derive_client_traffic_key.txt";
  case TypeOfDerivation::SERVER_HANDSHAKE_KEY:
    return "derive_server_handshake_key.txt";
  case TypeOfDerivation::SERVER_TRAFFIC_KEY:
    return "derive_server_traffic_key.txt";
  case TypeOfDerivation::SERVER_HTS:
    return "derive_shts.txt";
  case TypeOfDerivation::CLIENT_HTS:
    return "derive_chts.txt";
  case TypeOfDerivation::DHS:
    return "derive_dhs.txt";
  case TypeOfDerivation::MS:
    return "derive_ms.txt";
  case TypeOfDerivation::CATS:
    return "derive_cats.txt";
  case TypeOfDerivation::SATS:
    return "derive_sats.txt";
  case TypeOfDerivation::EMS:
    return "derive_ems.txt";
  }
}

/**
   SplitData. This struct exists solely to represent a succinct return type
   for splitting the test_data into two separate arrays (see DerivationTestCase
 for more).
   @tparam size: the size of the input test case. This is multiplied by
 4 to make it so that each output char corresponds to a single bit of the input
 across both arrays.
 **/
template <unsigned size> struct SplitData {
  /**
     client_out. This array holds the client output, which corresponds to the
  first size * 4 bits of the input data.
  **/
  std::array<bool, size * 4> client_out;
  /**
   sever_out. This array holds the client output, which corresponds to the
second size * 4 bits of the input data.
  **/
  std::array<bool, size * 4> server_out;
};

/**
   DerivationTestCase. This struct models a test case for the derivation
circuits. This struct exists solely to make sure that the outputs of our
circuits are identical to the circuits produced by n-for-1 auth's circuits. We
thank the authors of the n-for-1-auth project for providing these in their
source code.

   This struct acts as follows. Firstly, it contains array holding some known
test data. In all cases these were lifted directly from n-for-1-auth's
generate_handshake_circuits.cpp file. The second array it holds is the answer
produced by the circuits produced by the n-for-1-auth codebase. In this
situation, the output was generated by calling the "print_many_bytes_function"
(in n-for-1-auth's generate_handshake_circuits.cpp) with the result of the
circuit.
@tparam in_size: the number of chars in the test_data.
@tparam out_size: the number of chars in the expected answer.
**/
template <unsigned in_size = 32, unsigned out_size = 16>
struct DerivationTestCase {
  // We require that both in_size and out_size are multiples of 2.
  static_assert(in_size % 2 == 0, "Error: in_size is not a multiple of 2");
  static_assert(out_size % 2 == 0, "Error: out_size is not a multiple of 2");

  /**
     test_data. This is the test data lifted from n-for-1-auth.
  **/
  std::array<unsigned char, in_size> test_data;
  /**
     expected_answer. This is the answer produced by the n-for-1-auth circuits.
     Note that here we are assuming AES.
  **/
  std::array<unsigned char, out_size> expected_answer;

  /**
     copy_test_data. This function returns a SplitData object with the
     first `in_size/2` entries of
     `test_data` in `client_out` and the second `in_size/2` entries of
  `test_data` in `server_out`. This function does not throw or modify this test
  object.
  **/
  constexpr SplitData<in_size> copy_test_data() const noexcept {
    return SplitData<in_size>{
        chars_to_bools<in_size / 2>(test_data.data()),
        chars_to_bools<in_size / 2>(test_data.data() + in_size / 2)};
  }
};

template <TypeOfDerivation mode>
static constexpr DerivationTestCase<32, 32>
get_test_data_for_secret() noexcept {
  // This function provides test cases from n-for-1-auth
  // for deriving traffic secrets.
  // In particular, this function should only be called by DeriveDHS,
  // DeriveSCHTS, or DeriveMS.
  // Note that some of these test cases are repeats.
  static_assert(
      mode == TypeOfDerivation::SERVER_HTS ||
          mode == TypeOfDerivation::CLIENT_HTS ||
          mode == TypeOfDerivation::DHS || mode == TypeOfDerivation::MS ||
          mode == TypeOfDerivation::CATS || mode == TypeOfDerivation::SATS ||
          mode == TypeOfDerivation::EMS,
      "Error: cannot call get_test_data_for_secret with supplied mode");

  constexpr std::array<unsigned char, 32> handshake_test_data{
      0xfb, 0x9f, 0xc8, 0x06, 0x89, 0xb3, 0xa5, 0xd0, 0x2c, 0x33, 0x24,
      0x3b, 0xf6, 0x9a, 0x1b, 0x1b, 0x20, 0x70, 0x55, 0x88, 0xa7, 0x94,
      0x30, 0x4a, 0x6e, 0x71, 0x20, 0x15, 0x5e, 0xdf, 0x14, 0x9a};

  constexpr std::array<unsigned char, 32> chts_expected{
      0xFF, 0x0E, 0x5B, 0x96, 0x52, 0x91, 0xC6, 0x08, 0xC1, 0xE8, 0xCD,
      0x26, 0x7E, 0xEF, 0xC0, 0xAF, 0xCC, 0x5E, 0x98, 0xA2, 0x78, 0x63,
      0x73, 0xF0, 0xDB, 0x47, 0xB0, 0x47, 0x86, 0xD7, 0x2A, 0xEA};
  constexpr std::array<unsigned char, 32> shts_expected{
      0xA2, 0x06, 0x72, 0x65, 0xE7, 0xF0, 0x65, 0x2A, 0x92, 0x3D, 0x5D,
      0x72, 0xAB, 0x04, 0x67, 0xC4, 0x61, 0x32, 0xEE, 0xB9, 0x68, 0xB6,
      0xA3, 0x2D, 0x31, 0x1C, 0x80, 0x58, 0x68, 0x54, 0x88, 0x14};

  constexpr std::array<unsigned char, 32> dhs_expected{
      0xDE, 0x9F, 0x5C, 0x98, 0xDB, 0x42, 0x61, 0xA4, 0x69, 0x11, 0xF1,
      0x34, 0x9C, 0x1B, 0xA2, 0xC8, 0x4D, 0xD8, 0x44, 0x82, 0x24, 0x9F,
      0x8F, 0x2C, 0xB3, 0xA9, 0x89, 0xE4, 0xE4, 0xA8, 0x04, 0xE6};

  constexpr std::array<unsigned char, 32> ms_expected{
      0x7F, 0x28, 0x82, 0xBB, 0x9B, 0x9A, 0x46, 0x26, 0x59, 0x41, 0x65,
      0x3E, 0x9C, 0x2F, 0x19, 0x06, 0x71, 0x18, 0x15, 0x1E, 0x21, 0xD1,
      0x2E, 0x57, 0xA7, 0xB6, 0xAC, 0xA1, 0xF8, 0x15, 0x0C, 0x8D};

  constexpr std::array<unsigned char, 32> ats_test_data{
      0x7f, 0x28, 0x82, 0xbb, 0x9b, 0x9a, 0x46, 0x26, 0x59, 0x41, 0x65,
      0x3e, 0x9c, 0x2f, 0x19, 0x06, 0x71, 0x18, 0x15, 0x1e, 0x21, 0xd1,
      0x2e, 0x57, 0xa7, 0xb6, 0xac, 0xa1, 0xf8, 0x15, 0x0c, 0x8d};

  constexpr std::array<unsigned char, 32> cats_expected_data{
      0xb8, 0x82, 0x22, 0x31, 0xc1, 0xd6, 0x76, 0xec, 0xca, 0x1c, 0x11,
      0xff, 0xf6, 0x59, 0x42, 0x80, 0x31, 0x4d, 0x03, 0xa4, 0xe9, 0x1c,
      0xf1, 0xaf, 0x7f, 0xe7, 0x3f, 0x8f, 0x7b, 0xe2, 0xc1, 0x1b};

  constexpr std::array<unsigned char, 32> sats_expected_data{
      0x3F, 0xC3, 0x5E, 0xA7, 0x06, 0x93, 0x06, 0x9A, 0x27, 0x79, 0x56,
      0xAF, 0xA2, 0x3B, 0x8F, 0x45, 0x43, 0xCE, 0x68, 0xAC, 0x59, 0x5F,
      0x2A, 0xAC, 0xE0, 0x5C, 0xD7, 0xA1, 0xC9, 0x20, 0x23, 0xD5};

  constexpr std::array<unsigned char, 32> ems_expected_data{
      0x07, 0x98, 0xFA, 0x25, 0xDA, 0x1E, 0x8B, 0x74, 0x87, 0xB2, 0x45,
      0xD7, 0xC4, 0xAF, 0x9B, 0x24, 0x98, 0x8D, 0xE3, 0xAE, 0xFA, 0x0E,
      0xF6, 0x32, 0x59, 0xFD, 0x6C, 0x9D, 0x0B, 0x52, 0xAE, 0xED};

  switch (mode) {
  case TypeOfDerivation::SERVER_HTS:
    return DerivationTestCase<32, 32>{handshake_test_data, shts_expected};
  case TypeOfDerivation::CLIENT_HTS:
    return DerivationTestCase<32, 32>{handshake_test_data, chts_expected};
  case TypeOfDerivation::DHS:
    return DerivationTestCase<32, 32>{handshake_test_data, dhs_expected};
  case TypeOfDerivation::MS:
    return DerivationTestCase<32, 32>{dhs_expected, ms_expected};
  case TypeOfDerivation::CATS:
    return DerivationTestCase<32, 32>{ats_test_data, cats_expected_data};
  case TypeOfDerivation::SATS:
    return DerivationTestCase<32, 32>{ats_test_data, sats_expected_data};
  case TypeOfDerivation::EMS:
    return DerivationTestCase<32, 32>{ats_test_data, ems_expected_data};
  };
}

template <TypeOfDerivation mode>
static constexpr DerivationTestCase<32, 16>
get_test_data_for_iv_or_key() noexcept {

  // This function provides test cases from n-for-1-auth for deriving the IV
  // or the key.
  // Note that some of these test cases are repeats: however,
  // in case we ever change these values later, they're
  // separate in this file.
  constexpr std::array<unsigned char, 32> handshake_iv_test_data{
      0xff, 0x0e, 0x5b, 0x96, 0x52, 0x91, 0xc6, 0x08, 0xc1, 0xe8, 0xcd,
      0x26, 0x7e, 0xef, 0xc0, 0xaf, 0xcc, 0x5e, 0x98, 0xa2, 0x78, 0x63,
      0x73, 0xf0, 0xdb, 0x47, 0xb0, 0x47, 0x86, 0xd7, 0x2a, 0xea};

  constexpr std::array<unsigned char, 16> handshake_iv_answer{
      0xCE, 0xDA, 0xD4, 0xDC, 0x4A, 0xD2, 0xCC, 0xEA,
      0x24, 0xCD, 0x89, 0xB5, 0x8B, 0x7A, 0x39, 0xB5};

  constexpr std::array<unsigned char, 32> traffic_iv_test_data{
      0xb8, 0x82, 0x22, 0x31, 0xc1, 0xd6, 0x76, 0xec, 0xca, 0x1c, 0x11,
      0xff, 0xf6, 0x59, 0x42, 0x80, 0x31, 0x4d, 0x03, 0xa4, 0xe9, 0x1c,
      0xf1, 0xaf, 0x7f, 0xe7, 0x3f, 0x8f, 0x7b, 0xe2, 0xc1, 0x1b};

  constexpr std::array<unsigned char, 16> traffic_iv_answer{
      0xF1, 0x15, 0x6A, 0x67, 0xE0, 0xA3, 0xC1, 0x1C,
      0xF5, 0x6F, 0x9F, 0x6C, 0x22, 0x73, 0x1D, 0x21};

  constexpr std::array<unsigned char, 32> handshake_key_test_data{
      0xff, 0x0e, 0x5b, 0x96, 0x52, 0x91, 0xc6, 0x08, 0xc1, 0xe8, 0xcd,
      0x26, 0x7e, 0xef, 0xc0, 0xaf, 0xcc, 0x5e, 0x98, 0xa2, 0x78, 0x63,
      0x73, 0xf0, 0xdb, 0x47, 0xb0, 0x47, 0x86, 0xd7, 0x2a, 0xea};

  constexpr std::array<unsigned char, 16> handshake_key_answer{
      0x71, 0x54, 0xF3, 0x14, 0xE6, 0xBE, 0x7D, 0xC0,
      0x08, 0xDF, 0x2C, 0x83, 0x2B, 0xAA, 0x1D, 0x39};

  constexpr std::array<unsigned char, 32> traffic_key_test_data{
      0xb8, 0x82, 0x22, 0x31, 0xc1, 0xd6, 0x76, 0xec, 0xca, 0x1c, 0x11,
      0xff, 0xf6, 0x59, 0x42, 0x80, 0x31, 0x4d, 0x03, 0xa4, 0xe9, 0x1c,
      0xf1, 0xaf, 0x7f, 0xe7, 0x3f, 0x8f, 0x7b, 0xe2, 0xc1, 0x1b};

  constexpr std::array<unsigned char, 16> traffic_key_answer{
      0x49, 0x13, 0x4B, 0x95, 0x32, 0x8F, 0x27, 0x9F,
      0x01, 0x83, 0x86, 0x05, 0x89, 0xAC, 0x67, 0x07};

  if constexpr (mode == TypeOfDerivation::CLIENT_HANDSHAKE_IV ||
                mode == TypeOfDerivation::SERVER_HANDSHAKE_IV) {
    return DerivationTestCase<32, 16>{handshake_iv_test_data,
                                      handshake_iv_answer};
  } else if constexpr (mode == TypeOfDerivation::CLIENT_TRAFFIC_IV ||
                       mode == TypeOfDerivation::SERVER_TRAFFIC_IV) {
    return DerivationTestCase<32, 16>{traffic_iv_test_data, traffic_iv_answer};
  } else if constexpr (mode == TypeOfDerivation::CLIENT_HANDSHAKE_KEY ||
                       mode == TypeOfDerivation::SERVER_HANDSHAKE_KEY) {
    return DerivationTestCase<32, 16>{handshake_key_test_data,
                                      handshake_key_answer};
  } else if constexpr (mode == TypeOfDerivation::CLIENT_TRAFFIC_KEY ||
                       mode == TypeOfDerivation::SERVER_TRAFFIC_KEY) {
    return DerivationTestCase<32, 16>{traffic_key_test_data,
                                      traffic_key_answer};
  }
}

template <unsigned int length> static void DeriveHS() {
  static_assert(length == 256 || length == 384 || length == 521,
                "Error: mismatched size");
  emp::setup_plain_prot(true, "derive_hs_" + std::to_string(length) + ".txt");
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  assert(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  // This function naively looks like this:
  // HS = HKDF.Extract(dES, DHE), where DHE is the shared secret.
  // Because DHE and HS both need to be shared, we apply the following input
  // format:
  // 1. dES is the public input comprising the first 256-bits.
  // 2. DHE is split into two `length` long chunks, which we then add modulo
  // the relevant prime,
  //    and
  // 3. The final 256 bits are masks for the output: each party inputs
  // 128-bits of this input,
  //    which is then xored with the output of the HKDF function. This is to
  //    make the split of the shares easier to compute on either side. This is
  //    done inside extract_secret_each.

  // For the circuit evaluation, we'll just generate random data of the right
  // size.
  // Note that ES = HKDF.Extract(0, 0) and dES = HKDF.Expand(ES, "derived",
  // Hash(0)), which is a constant: so we can just use this a priori as a public
  // input.
  constexpr std::array<unsigned char, 32> dES{
      0x6F, 0x26, 0x15, 0xA1, 0x08, 0xC7, 0x02, 0xC5, 0x67, 0x8F, 0x54,
      0xFC, 0x9D, 0xBA, 0xB6, 0x97, 0x16, 0xC0, 0x76, 0x18, 0x9C, 0x48,
      0x25, 0x0C, 0xEB, 0xEA, 0xC3, 0x57, 0x6C, 0x36, 0x11, 0xBA};

  auto context = chars_to_blocks<32>(dES.data());

  // Now we need to generate two random secrets that are `length`-bits in
  // size. This is just for the sake of this circuit generation: the exact
  // values don't matter. Note however that the prime very much _does_ matter.
  bssl::UniquePtr<EC_GROUP> curve(get_curve<length>());
  const auto order = EC_GROUP_get0_order(curve.get());

  // Now we'll make the random data.
  BIGNUM *a = BN_CTX_get(bn_ctx.get());
  BIGNUM *b = BN_CTX_get(bn_ctx.get());
  assert(a && b);

  // We need to turn the order into a bool array.
  auto p_as_arr = serialise_bignum<length>(order);
  BN_rand_range_ex(a, 1, order);
  BN_rand_range_ex(b, 1, order);

  auto a_as_arr = serialise_bignum<length>(a);
  auto b_as_arr = serialise_bignum<length>(b);

  // Now we'll call the addition routine. The answer size will be exactly
  // `length` blocks.
  // WARNING: this is a hack!

  // Essentially, in emp each block corresponds to a single bit. This means
  // that doing byte-wise operations on the block is a bit difficult. To
  // circumvent this, we round up only if the input prime is 521 bits (since
  // 256 and 384 are both multiples of 8).
  constexpr auto size = length == 521 ? 528 : length;
  emp::block addition[size];
  if constexpr (length == 521) {
    const auto zero = emp::CircuitExecution::circ_exec->public_label(false);
    std::fill(std::begin(addition) + 521, std::end(addition), zero);
  }

  CircuitSynthesis::add_two_mod_p(a_as_arr.data(), b_as_arr.data(),
                                  p_as_arr.data(), addition, length);

  // So now we've fed in both dES and the addition mod p. This forms
  // the first lot of our data, which we'll then feed into hkdf_expand_label.
  emp::block derived_secret[256];

  // derived_secret = HKDF.Extract(dES, DHE), with DHE = addition and
  // dES = context.
  CircuitSynthesis::hkdf_extract(EmpBlockNonOwningSpan{context.data(), 256},
                                 EmpBlockNonOwningSpan{addition, size},
                                 derived_secret);
  // Note: the masks are generated and produced in here,
  extract_secret_each(derived_secret);
  emp::finalize_plain_prot();
}

template <TypeOfDerivation mode>
static constexpr std::array<unsigned char, 32> get_hash_test_data() {
  static_assert(mode == TypeOfDerivation::SERVER_HTS ||
                    mode == TypeOfDerivation::CLIENT_HTS ||
                    mode == TypeOfDerivation::CATS ||
                    mode == TypeOfDerivation::SATS ||
                    mode == TypeOfDerivation::EMS,
                "Error: cannot instantiate get_hash_test_data");

  constexpr std::array<unsigned char, 32> hello_hash_test_data{
      0xda, 0x75, 0xce, 0x11, 0x39, 0xac, 0x80, 0xda, 0xe4, 0x04, 0x4d,
      0xa9, 0x32, 0x35, 0x0c, 0xf6, 0x5c, 0x97, 0xcc, 0xc9, 0xe3, 0x3f,
      0x1e, 0x6f, 0x7d, 0x2d, 0x4b, 0x18, 0xb7, 0x36, 0xff, 0xd5};

  constexpr std::array<unsigned char, 32> handshake_hash_test_data{
      0x22, 0x84, 0x4b, 0x93, 0x0e, 0x5e, 0x0a, 0x59, 0xa0, 0x9d, 0x5a,
      0xc3, 0x5f, 0xc0, 0x32, 0xfc, 0x91, 0x16, 0x3b, 0x19, 0x38, 0x74,
      0xa2, 0x65, 0x23, 0x6e, 0x56, 0x80, 0x77, 0x37, 0x8d, 0x8b};

  switch (mode) {
  case TypeOfDerivation::SERVER_HTS:
  case TypeOfDerivation::CLIENT_HTS:
    return hello_hash_test_data;
  default:
    return handshake_hash_test_data;
  }
}

template <TypeOfDerivation mode, bool testing>
static void DeriveSessionSecrets() {
  // This function just derives the expansion circuit for deriving the client
  // handshake secret.
  static_assert(mode == TypeOfDerivation::SERVER_HTS ||
                    mode == TypeOfDerivation::CLIENT_HTS ||
                    mode == TypeOfDerivation::EMS ||
                    mode == TypeOfDerivation::SATS ||
                    mode == TypeOfDerivation::CATS,
                "Error: DeriveSCHTS only works with the listed types");

  emp::setup_plain_prot(!testing, get_filename<mode>());

  // We follow the following convention: Alice is the prover, Bob is the
  // verifier. Note that as per the convention described in deriveHS, Alice
  // holds the "lower" 128 entries of HS, whereas Bob holds the "upper 128"
  // entries of HS.

  // This comes from n-for-1-auth.
  constexpr auto hash_test_data = get_hash_test_data<mode>();

  const auto test_data = get_test_data_for_secret<mode>();
  const auto split_data = test_data.copy_test_data();
  auto alice_input = split_data.client_out;
  auto bob_input = split_data.server_out;

  // We feed them in into a singular array.
  emp::block joint_input[256];
  emp::ProtocolExecution::prot_exec->feed(joint_input, emp::ALICE,
                                          alice_input.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(joint_input + 128, emp::BOB,
                                          bob_input.data(), 128);

  auto hash_bool = chars_to_bools<32>(hash_test_data.data());

  emp::block hash[256];
  emp::ProtocolExecution::prot_exec->feed(hash, emp::ALICE, hash_bool.data(),
                                          256);
  emp::block derived[256];

  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{joint_input, 256}, get_tag<mode>(),
      EmpBlockNonOwningSpan{hash, 256}, derived, 32);

  // If testing, we'll check that the outputs are as expected.
  if constexpr (testing) {
    const auto result = print_hash_to_string<32>(derived);
    assert(result == test_data.expected_answer);
  } else {
    // Now the same xoring as before.
    extract_secret_each(derived);
  }
  emp::finalize_plain_prot();
}

template <bool testing> static void DeriveDHS() {
  static constexpr auto mode = TypeOfDerivation::DHS;
  // This function is essentially the same as deriveCHTS, but with
  // a slight optimisation: namely, we use the empty hash for the final
  // set of input bits during circuit construction.
  // In n-for-1-auth this function is the first part of DeriveMasterSecret.
  emp::setup_plain_prot(!testing, get_filename<mode>());

  auto context = chars_to_blocks<32>(get_empty_hash().data());

  // Now we've got those done, we can just do the expansion as before.
  const auto test_data = get_test_data_for_secret<mode>();
  const auto split_data = test_data.copy_test_data();
  auto alice_input = split_data.client_out;
  auto bob_input = split_data.server_out;

  emp::block joint_input[256];
  emp::ProtocolExecution::prot_exec->feed(joint_input, emp::ALICE,
                                          alice_input.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(joint_input + 128, emp::BOB,
                                          bob_input.data(), 128);

  emp::block dhs[256];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{joint_input, 256}, get_tag<mode>(),
      EmpBlockNonOwningSpan{context.data(), 256}, dhs, 32);

  if constexpr (testing) {
    const auto result = print_hash_to_string<32>(dhs);
    assert(result == test_data.expected_answer);
  } else {
    extract_secret_each(dhs);
  }

  emp::finalize_plain_prot();
}

template <bool testing> static void DeriveMS() {
  static constexpr auto mode = TypeOfDerivation::MS;
  // This function is essentially the same as deriveDHS, but with
  // an extra label expansion at the end. This is because this part of the
  // PRF is executed _after_ we've derived the dHS in our application.

  emp::setup_plain_prot(!testing, get_filename<mode>());

  // Now we've got those done, we can just do the expansion as before.
  // Note that the value returned below from get_test_data_for_secret
  // is the output of deriveDHS.
  const auto test_data = get_test_data_for_secret<mode>();
  const auto split_data = test_data.copy_test_data();
  auto alice_input = split_data.client_out;
  auto bob_input = split_data.server_out;

  emp::block joint_input[256];
  emp::ProtocolExecution::prot_exec->feed(joint_input, emp::ALICE,
                                          alice_input.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(joint_input + 128, emp::BOB,
                                          bob_input.data(), 128);

  const auto zero = emp::CircuitExecution::circ_exec->public_label(false);
  emp::block zero_key[256];
  std::fill(zero_key, zero_key + 256, zero);
  emp::block derived_secret[256];
  CircuitSynthesis::hkdf_extract(EmpBlockNonOwningSpan{joint_input, 256},
                                 EmpBlockNonOwningSpan{zero_key, 256},
                                 derived_secret);

  if constexpr (testing) {
    const auto result = print_hash_to_string<32>(derived_secret);
    assert(result == test_data.expected_answer);
  } else {
    extract_secret_each(derived_secret);
  }

  emp::finalize_plain_prot();
}

template <TypeOfDerivation mode, bool testing = false> static void DeriveATS() {
  static_assert(mode == TypeOfDerivation::CATS ||
                    mode == TypeOfDerivation::SATS ||
                    mode == TypeOfDerivation::EMS,
                "Error: cannot call deriveATS with supplied mode");
}

template <TypeOfDerivation mode, bool testing = false>
static void DeriveIVOrKey() {
  // We change the name of the output file depending on the template argument.
  // We only produce the actual circuits in non-test modes though.
  emp::setup_plain_prot(!testing, get_filename<mode>());

  // We use the hardcoded test data to make sure everything works.
  static constexpr auto data = get_test_data_for_iv_or_key<mode>();

  // Note that unlike n-for-1-auth we expect this to have been split here,
  // so we'll split the test data in half like this.
  const auto split = data.copy_test_data();
  auto client_secret = split.client_out;
  auto server_secret = split.server_out;

  emp::block joint_secret[256];
  emp::ProtocolExecution::prot_exec->feed(joint_secret, emp::ALICE,
                                          client_secret.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(joint_secret + 128, emp::BOB,
                                          server_secret.data(), 128);

  // We also have to feed in the input masks here before we do any work.
  bool bob_mask[128];
  for (auto &v : bob_mask) {
    v = rand();
  }

  // This does mean that Bob feeds in more input than Alice. We expect the
  // library of choice to deal with this.
  emp::block bob_mask_input[128];
  emp::ProtocolExecution::prot_exec->feed(bob_mask_input, emp::BOB, bob_mask,
                                          128);

  // We assume AES-128 here, which means we always need 128-bit output.
  emp::block derived[128];

  // This span isn't actually used.
  emp::block empty_span;

  // Now we produce the value.
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{joint_secret, 256}, get_tag<mode>(),
      EmpBlockNonOwningSpan{&empty_span, 0}, derived, 16);

  // In testing mode, all we do here is check that the produced value is the
  // same as we expected.
  if constexpr (testing) {
    // Firstly we reveal the output in derived.
    const auto revealed = print_hash_to_string<16>(derived);
    static_assert(sizeof(revealed) == sizeof(data.expected_answer),
                  "Error: revealed is not 128-bits in size");
    assert(revealed == data.expected_answer);
  } else {
    // Note that this is in an "else", as we've already revealed the outputs
    // publicly in the other case above.

    // At the point we need to split up the produced value.
    // This is trickier than the other functions: we cannot use the extract
    // secret function here, because we're using a 128-bit key: this would
    // open us up to a 2^65 bit attack for both the AES key and the IV, which
    // is less than ideal. To circumvent this, we use a classical idea: Bob
    // supplies an additional 128-bit mask (`mask`) as input. Alice received
    // `derived xor mask` as her share, whilst Bob keeps `mask` as theirs.
    // This is a full secret share, but it also doesn't rely on us doing any
    // clever splitting.

    emp::block alice_out[128];
    for (unsigned i = 0; i < 128; i++) {
      alice_out[i] = emp::CircuitExecution::circ_exec->xor_gate(
          derived[i], bob_mask_input[i]);
    }

    bool alice_out_bool[128];
    // Bob gets nothing, as they already know the mask they supplied.
    emp::ProtocolExecution::prot_exec->reveal(alice_out_bool, emp::ALICE,
                                              alice_out, 128);
  }
  emp::finalize_plain_prot();
}

static void assert_valid_filepath(const char *const filepath) noexcept {
  // This function checks that filepath corresponds to a valid file.
  // Otherwise, we assert(false). This will only do anything in debug builds:
  // otherwise, it's an empty function.
  FILE *f = std::fopen(filepath, "r");
  assert(f);
  std::fclose(f);
}

static void DeriveAESEncryption() {
  // This function produces a circuit for a singular AES encryption.
  // This is only useful for our use case: essentially, the keys produced by
  // DeriveIVOrKey are masked with a mask, m, supplied by Bob. Alice receives k
  // \xor m, Bob receives nothing. Whenever they wish to do an AES encryption,
  // Bob needs to supply m, whilst Alice supplies k /xor m. The AES circuit, as
  // pre-processing, needs to compute m /xor k /xor m = k, before the encryption
  // can be carried out. This function just appends this pre-processing.
  emp::setup_plain_prot(true, "aes_128_full_masked.txt");

  // We'll use some random data to test this.
  const auto data =
      get_test_data_for_iv_or_key<TypeOfDerivation::CLIENT_HANDSHAKE_KEY>()
          .test_data;

  // A test key is already stored elsewhere in this program.
  const auto key =
      get_test_data_for_iv_or_key<TypeOfDerivation::CLIENT_HANDSHAKE_KEY>()
          .expected_answer;

  // This is just a randomly generated mask.
  constexpr std::array<unsigned char, 16> bob_mask{
      0x67, 0xC6, 0x69, 0x73, 0x51, 0xFF, 0x4A, 0xEC,
      0x29, 0xCD, 0xBA, 0xAB, 0xF2, 0xFB, 0xE3, 0x46};

  // Alice's input consists of this along with some random data.
  auto alice_message = chars_to_bools<16>(data.data());
  auto alice_key = chars_to_bools<16>(key.data());
  auto bob_bools = chars_to_bools<16>(bob_mask.data());
  std::array<bool, 128> bob_blank;
  for (unsigned i = 0; i < 128; i++) {
    bob_blank[i] = rand();
  }

  emp::block alice_message_input[128];
  emp::block alice_key_input[128];

  emp::block bob_key_input[128];
  emp::block bob_extra_input[128];

  emp::PlainProt::prot_exec->feed(alice_message_input, emp::ALICE,
                                  alice_message.data(), 128);
  emp::PlainProt::prot_exec->feed(alice_key_input, emp::ALICE, alice_key.data(),
                                  128);

  emp::PlainProt::prot_exec->feed(bob_key_input, emp::BOB, bob_bools.data(),
                                  128);
  emp::PlainProt::prot_exec->feed(bob_extra_input, emp::BOB, bob_blank.data(),
                                  128);

  // Derive the circuit key.
  emp::block c_key[128];
  for (unsigned i = 0; i < 128; i++) {
    c_key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_key_input[i],
                                                          bob_key_input[i]);
  }

  // Encrypt the block. It needs to be double packed, with the keys in the first
  // 128 bits and the message in the next 128.
  emp::block aes_in[256];
  memcpy(aes_in, c_key, sizeof(emp::block) * 128);
  memcpy(aes_in + 128, alice_message_input, sizeof(emp::block) * 128);

  emp::block out[128];
  assert_valid_filepath(CircuitSynthesis::AES128_FULL_FILEPATH);
  emp::BristolFormat bf(CircuitSynthesis::AES128_FULL_FILEPATH);
  bf.compute(out, aes_in, aes_in);

  // Both parties learn the result.
  bool result[128];
  emp::ProtocolExecution::prot_exec->reveal(result, emp::PUBLIC, out, 128);
  emp::finalize_plain_prot();
}

// COMBINED KEYING MATERIAL CIRCUITS
// This portion of the code actually combines all of the individual key
// derivation circuits into one, larger circuit. The point of this is to reduce
// the practical running time of these circuits: most of the information is
// repeated anyway, and this means that garbled circuit libraries like EMP can
// typically run faster. This also contains duplicate code from the other
// functions.
template <unsigned int length> static void ProduceCombinedCircuit() noexcept {
  static_assert(length == 256 || length == 384 || length == 521,
                "Error: mismatched length");
  emp::setup_plain_prot(true, "derive_handshake_secrets_" +
                                  std::to_string(length) + ".txt");
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  assert(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  // This function is similar to DeriveHS. We naively compute HS =
  // HKDF.Extract(dES, DHE), and then feed the result into the computation for
  // CHTS, SHTS and dHS. Each party needs to supply their share of the DHE value
  // (comprising of |length| bits) and a mask that is big enough to XOR out
  // their portion of the secret. Because we split secrets evenly, this is
  // expected to be 512 bits for the secrets up to (and including) dHS. We also
  // require that the verifier (Bob) inputs the transcript, to prevent the
  // prover (Alice) from cheating.

  // This is the fixed dES value.
  constexpr std::array<unsigned char, 32> dES{
      0x6F, 0x26, 0x15, 0xA1, 0x08, 0xC7, 0x02, 0xC5, 0x67, 0x8F, 0x54,
      0xFC, 0x9D, 0xBA, 0xB6, 0x97, 0x16, 0xC0, 0x76, 0x18, 0x9C, 0x48,
      0x25, 0x0C, 0xEB, 0xEA, 0xC3, 0x57, 0x6C, 0x36, 0x11, 0xBA};

  auto context = chars_to_blocks<32>(dES.data());

  // Now we need to generate two random secrets that are `length`-bits in size.
  // This is just for circuit generation. We simply generate over the base field
  // of the corresponding elliptic curve.
  bssl::UniquePtr<EC_GROUP> curve(get_curve<length>());
  assert(curve);
  BIGNUM *order = BN_CTX_get(bn_ctx.get());
  assert(order);
  if (!EC_GROUP_get_curve_GFp(curve.get(), order, nullptr, nullptr,
                              bn_ctx.get())) {
    std::abort();
  }

  // `a` is Alice's input, `b` is Bob's.
  BIGNUM *a = BN_CTX_get(bn_ctx.get());
  BIGNUM *b = BN_CTX_get(bn_ctx.get());
  assert(a && b);

  // We need to turn the order into a bool array.
  auto p_as_arr = serialise_bignum<length>(order);
  BN_rand_range_ex(a, 1, order);
  BN_rand_range_ex(b, 1, order);

  // And the randomly generated numbers too.
  auto a_as_arr = serialise_bignum<length>(a);
  auto b_as_arr = serialise_bignum<length>(b);

  // Now we'll call the addition routine. The answer size will be exactly
  // `length` blocks.
  // WARNING: this is a hack!

  // Essentially, in emp each block corresponds to a single bit. This means
  // that doing byte-wise operations on the block is a bit difficult. To
  // circumvent this, we round up only if the input prime is 521 bits (since
  // 256 and 384 are both multiples of 8).
  constexpr auto size = length == 521 ? 528 : length;
  emp::block addition[size];
  if constexpr (length == 521) {
    const auto zero = emp::CircuitExecution::circ_exec->public_label(false);
    std::fill(std::begin(addition) + 521, std::end(addition), zero);
  }

  // We'll store the prime input in this block.
  emp::block p_block[size];

  // WARNING: this may be confusing if you aren't familiar with certain features
  // of EMP (this took the author of this code a while to figure out too!).
  // Essentially, emp's circuit generation tools work best if you feed in all of
  // the inputs at the beginning. It turns out that emp labels each gate with a
  // unique ID. For some reason, if inputs are fed in after computation, then
  // emp gets confused and so the circuits essentially break during runtime.
  // This seems to be because Bristol Format circuits assume that the lower
  // input wires are for the first party, whereas the upper input wires are for
  // the second: this can get confusing with emp, where wires are labelled as
  // they are fed in (and so input mismatches are easy to create). To fix this,
  // we feed everything in first. This is in order of use, but with the
  // exception that the additive shares must go last. We also feed in each input
  // in order of the party: we put Alice's inputs in the low wires and Bob's in
  // the upper wires. This is deliberate to prevent circuits from being
  // mismatched. We also break an abstraction around the addition circuits and
  // just call them directly.
  constexpr auto h2_test_data =
      get_hash_test_data<TypeOfDerivation::CLIENT_HTS>();
  auto h2_bool = chars_to_bools<32>(h2_test_data.data());
  emp::block h2[256];

  // We need the all zero string for the MS.
  static constexpr std::array<bool, 256> zero{};
  emp::block zero_key[256];

  // H("") is constant for a fixed hash function. Since it's used in the
  // derivation of the dHS we just place it here.
  auto h0_bool = chars_to_bools<32>(get_empty_hash().data());
  emp::block h0[256];

  // Public info first.
  emp::ProtocolExecution::prot_exec->feed(h0, emp::PUBLIC, h0_bool.data(), 256);
  emp::ProtocolExecution::prot_exec->feed(zero_key, emp::PUBLIC, zero.data(),
                                          256);
  emp::ProtocolExecution::prot_exec->feed(p_block, emp::PUBLIC, p_as_arr.data(),
                                          size);

  // Now we'll set up the rest of our inputs. We do everything in a particular
  // order to make sure the wires are consistent. This does involve breaking a
  // particular abstraction around addition, because we need to make sure
  // everything is fed in correctly.

  // We have to feed in two masks for xoring, since emp-ag2pc doesn't obscure
  // outputs, which we need.
  // In total we need:
  // 128 bits for each derived secret (so 768 bits per party) (640 here comes
  // from the 6 secrets dHE, CHTS, SHTS, DHS, MS and the AES key).
  constexpr auto mask_bits = 768;
  bool alice_mask[mask_bits], bob_mask[mask_bits];
  for (unsigned i = 0; i < mask_bits; i++) {
    alice_mask[i] = rand();
    bob_mask[i] = rand();
  }

  emp::block alice_mask_block[mask_bits], bob_mask_block[mask_bits];
  emp::block alice_share_in[length], bob_share_in[length];

  // WARNING WARNING WARNING: this is going to be very confusing...
  // We need to feed in Bob's inputs first, and then Alice's.
  // Why? Well, it's because of an emp-ag2pc bug. This is explained in more
  // detail in EmpWrapperAG2PC.cpp, but essentially emp-ag2pc treats the second
  // set of input wires as Alice's input, which means we need to feed in Bob's
  // input first to make sure that everything lines up properly.

  // So, Bob's first.
  emp::block bob_empty[256];
  emp::ProtocolExecution::prot_exec->feed(bob_empty, emp::BOB, h2_bool.data(),
                                          256); //
  emp::ProtocolExecution::prot_exec->feed(bob_mask_block, emp::BOB, bob_mask,
                                          mask_bits);
  emp::ProtocolExecution::prot_exec->feed(bob_share_in, emp::BOB,
                                          b_as_arr.data(), length);

  // Then Alice's.
  emp::ProtocolExecution::prot_exec->feed(h2, emp::ALICE, h2_bool.data(), 256);
  emp::ProtocolExecution::prot_exec->feed(alice_mask_block, emp::ALICE,
                                          alice_mask, mask_bits);
  emp::ProtocolExecution::prot_exec->feed(alice_share_in, emp::ALICE,
                                          a_as_arr.data(), length);

  // Copy over the wires for the right inputs. This is an abstraction break.
  emp::block add_in[3 * length];
  memcpy(add_in + 0 * length, p_block, sizeof(emp::block) * length);
  memcpy(add_in + 1 * length, bob_share_in, sizeof(emp::block) * length);
  memcpy(add_in + 2 * length, alice_share_in, sizeof(emp::block) * length);

  static constexpr auto file_path = []() {
    if constexpr (length == 256) {
      return CircuitSynthesis::MA_256_FILEPATH;
    } else if constexpr (length == 384) {
      return CircuitSynthesis::MA_384_FILEPATH;
    } else if constexpr (length == 521) {
      return CircuitSynthesis::MA_521_FILEPATH;
    }

    // Because of the static assert this is definitely true: however, the
    // compiler may not be clever enough to know that.
    assert(false);
  }();

  // We'll make sure the file actually exists (in debug mode only!)
  assert_valid_filepath(file_path);

  emp::BristolFashion bf(file_path);

  // Now we'll run the addition.
  bf.compute(addition, add_in);

  // The outputs of the circuits here are actually different from what the HKDF
  // functions expect. Briefly, the HKDF functions expect little-endian input
  // with the bits in a reasonable order. However, for some reason our circuits
  // output them in big endian order with the bits _reveresed_. We can resolve
  // this issue at generation time (so it doesn't cost the circuits anything),
  // but it's a known headache.
  CircuitSynthesis::rearrange_sum_bits(addition, size);

  // So now we've fed in both dES and the addition mod p. This forms
  // the first lot of our data, which we'll then feed into hkdf_expand_label.
  emp::block derived_secret[256];

  // Note: the calling syntax for this is backwards
  // derived_secret = HKDF.Extract(dES, DHE), with DHE = addition and
  // dES = context. NOTE: the size does not need to be padded here as the
  // sizes are already correct.
  CircuitSynthesis::hkdf_extract(EmpBlockNonOwningSpan{context.data(), 256},
                                 EmpBlockNonOwningSpan{addition, size},
                                 derived_secret);

  unsigned curr = 0;
  auto xor_secrets = [&](emp::block *blocks) {
    for (unsigned i = 0; i < 128; i++) {
      blocks[i] = emp::CircuitExecution::circ_exec->xor_gate(
          alice_mask_block[curr], blocks[i]);
      blocks[i + 128] = emp::CircuitExecution::circ_exec->xor_gate(
          bob_mask_block[curr], blocks[i + 128]);
      ++curr;
    }
  };

  // Now we can generate CHTS, SHTS and dHS.
  // CHTS
  emp::block derived_chts[256];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_secret, 256},
      get_tag<TypeOfDerivation::CLIENT_HTS>(), EmpBlockNonOwningSpan{h2, 256},
      derived_chts, 32);

  // SHTS.
  emp::block derived_shts[256];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_secret, 256},
      get_tag<TypeOfDerivation::SERVER_HTS>(), EmpBlockNonOwningSpan{h2, 256},
      derived_shts, 32);

  // dHS.
  emp::block derived_dhs[256];

  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_secret, 256},
      get_tag<TypeOfDerivation::DHS>(), EmpBlockNonOwningSpan{h0, 256},
      derived_dhs, 32);

  // MS
  emp::block ms[256];
  CircuitSynthesis::hkdf_extract(EmpBlockNonOwningSpan{derived_dhs, 256},
                                 EmpBlockNonOwningSpan{zero_key, 256}, ms);

  // We don't derive traffic keys here: instead, we just derive the fk_s, which
  // is jointly output. The reason for this is to instead allow the prover to do
  // this. The fk_s + certificate check already validates the transcript so far,
  // thanks to key independence.

  // This isn't actually used.
  emp::block *empty_span = nullptr;

  // fks
  emp::block fks[256];
  CircuitSynthesis::hkdf_expand_label(EmpBlockNonOwningSpan{derived_shts, 256},
                                      get_tag<TypeOfDerivation::FK_S>(),
                                      EmpBlockNonOwningSpan{empty_span, 0}, fks,
                                      32);

  emp::block aes_key[128];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_shts, 256},
      get_tag<TypeOfDerivation::SERVER_HANDSHAKE_KEY>(),
      EmpBlockNonOwningSpan{empty_span, 0}, aes_key, 16);

  emp::block iv[96];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_shts, 256},
      get_tag<TypeOfDerivation::SERVER_HANDSHAKE_IV>(),
      EmpBlockNonOwningSpan{empty_span, 0}, iv, 12);

  bool aes_out[128];
  bool iv_out[96];

  bool alice_out_bool[mask_bits], bob_out_bool[mask_bits];
  xor_secrets(derived_secret);
  xor_secrets(derived_chts);
  xor_secrets(derived_shts);
  xor_secrets(derived_dhs);
  xor_secrets(ms);

  for (unsigned i = 0; i < 128; i++) {
    aes_key[i] = emp::CircuitExecution::circ_exec->xor_gate(
        aes_key[i], alice_mask_block[curr]);
    curr++;
  }

  assert(curr == mask_bits);

  bool fks_out[256];

  emp::ProtocolExecution::prot_exec->reveal(alice_out_bool, emp::ALICE,
                                            derived_secret, 128);
  emp::ProtocolExecution::prot_exec->reveal(bob_out_bool, emp::BOB,
                                            derived_secret + 128, 128);

  emp::ProtocolExecution::prot_exec->reveal(alice_out_bool + 128, emp::ALICE,
                                            derived_chts, 128);
  emp::ProtocolExecution::prot_exec->reveal(bob_out_bool + 128, emp::BOB,
                                            derived_chts + 128, 128);

  emp::ProtocolExecution::prot_exec->reveal(alice_out_bool + 256, emp::ALICE,
                                            derived_shts, 128);
  emp::ProtocolExecution::prot_exec->reveal(bob_out_bool + 256, emp::BOB,
                                            derived_shts + 128, 128);

  emp::ProtocolExecution::prot_exec->reveal(alice_out_bool + 384, emp::ALICE,
                                            derived_dhs, 128);
  emp::ProtocolExecution::prot_exec->reveal(bob_out_bool + 384, emp::BOB,
                                            derived_dhs + 128, 128);

  emp::ProtocolExecution::prot_exec->reveal(alice_out_bool + 512, emp::ALICE,
                                            ms, 128);
  emp::ProtocolExecution::prot_exec->reveal(bob_out_bool + 512, emp::BOB,
                                            ms + 128, 128);

  emp::ProtocolExecution::prot_exec->reveal(fks_out, emp::PUBLIC, fks, 256);
  emp::ProtocolExecution::prot_exec->reveal(aes_out, emp::PUBLIC, aes_key, 128);
  emp::ProtocolExecution::prot_exec->reveal(iv_out, emp::PUBLIC, iv, 96);
  emp::finalize_plain_prot();
}

// We also have combined circuits for the traffic keys too. These are similar to
// the end of the above function, but they require less care and are smaller. In
// addition, they don't need to consider they input secret size, which makes
// everything much easier.
static void ProduceCombinedTrafficCircuits() noexcept {
  emp::setup_plain_prot(true, "derive_traffic_secrets_combined.txt");
  // Similarly to in the other combined circuit routines, we have to feed
  // secrets in in an ordered fashion. For consistency, we feed in Alice's input
  // first, and then Bob's.

  // The actual input order is MS share / H3 share / input mask.
  // We allow the label to be hardcoded.
  // Each party needs to input an additional 256 bits to mask the produced keys:
  // the IVs are revealed unmasked. We do not output CATS / SATS  etc here
  // because they're actually only used for the secret derivation, so we only
  // need 256 bits. Note that this function does not produce the RMS or the EMS!
  // Note that Bob's mask is only used to obscure the output of the circuit
  // from Alice: Alice's share is their mask bits.
  constexpr auto mask_bits = 256;

  // We represent the master secret and H3 as one array, for no particular
  // reason.
  std::array<bool, 256> ms_b;
  std::array<bool, 256> h3_b;

  // These are easier to reason about separately, though.
  std::array<bool, mask_bits> alice_mask_bits, bob_mask_bits;

  for (unsigned i = 0; i < 256; i++) {
    ms_b[i] = rand();
    h3_b[i] = rand();
  }

  for (unsigned i = 0; i < mask_bits; i++) {
    alice_mask_bits[i] = rand();
    bob_mask_bits[i] = rand();
  }

  emp::block ms[256]{}, h3[256]{};
  emp::block alice_mask[mask_bits], bob_mask[mask_bits];

  // Pass in Bob's (for the same reason as in the combined handshake circuits)
  // and then Alice's.
  // Note: Alice supplies the hash here, not Bob. Thus, Bob's input is just
  // redirected to nothingness.
  std::array<bool, 256> empty_b{};
  emp::block empty[256];

  emp::ProtocolExecution::prot_exec->feed(ms + 128, emp::BOB, ms_b.data() + 128,
                                          128);
  emp::ProtocolExecution::prot_exec->feed(empty, emp::BOB, empty_b.data(), 256);
  emp::ProtocolExecution::prot_exec->feed(bob_mask, emp::BOB,
                                          bob_mask_bits.data(), mask_bits);

  emp::ProtocolExecution::prot_exec->feed(ms, emp::ALICE, ms_b.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(h3, emp::ALICE, h3_b.data(), 256);
  emp::ProtocolExecution::prot_exec->feed(alice_mask, emp::ALICE,
                                          alice_mask_bits.data(), mask_bits);

  // CATS.
  emp::block derived_cats[256];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{ms, 256}, get_tag<TypeOfDerivation::CATS>(),
      EmpBlockNonOwningSpan{h3, 256}, derived_cats, 32);

  // SATS
  emp::block derived_sats[256];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{ms, 256}, get_tag<TypeOfDerivation::SATS>(),
      EmpBlockNonOwningSpan{h3, 256}, derived_sats, 32);

  // This isn't actually used.
  emp::block *empty_span = nullptr;

  // This has the same pain as in the combined handshake circuits, where the
  // output length is truncated.

  emp::block cts[128], ctiv[96];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_cats, 256},
      get_tag<TypeOfDerivation::CLIENT_TRAFFIC_KEY>(),
      EmpBlockNonOwningSpan{empty_span, 0}, cts, 16);

  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_cats, 256},
      get_tag<TypeOfDerivation::CLIENT_TRAFFIC_IV>(),
      EmpBlockNonOwningSpan{empty_span, 0}, ctiv, 12);

  // Server key and IV.
  emp::block sts[128], stiv[96];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_sats, 256},
      get_tag<TypeOfDerivation::SERVER_TRAFFIC_KEY>(),
      EmpBlockNonOwningSpan{empty_span, 0}, sts, 16);

  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_sats, 256},
      get_tag<TypeOfDerivation::SERVER_TRAFFIC_IV>(),
      EmpBlockNonOwningSpan{empty_span, 0}, stiv, 12);

  // We'll store the output in these.
  bool out_bool[mask_bits + 96 * 2];
  unsigned curr{};

  // XOR against both sets of masks.
  auto xor_double = [&](auto &in, const unsigned in_size) {
    for (unsigned i = 0; i < in_size; i++) {
      in[i] =
          emp::CircuitExecution::circ_exec->xor_gate(alice_mask[curr], in[i]);
      ++curr;
    }
  };

  xor_double(cts, 128);
  xor_double(sts, 128);

  assert(curr == mask_bits);

  emp::ProtocolExecution::prot_exec->reveal(out_bool, emp::PUBLIC, cts, 128);
  emp::ProtocolExecution::prot_exec->reveal(out_bool + 128, emp::PUBLIC, ctiv,
                                            96);
  emp::ProtocolExecution::prot_exec->reveal(out_bool + 128 + 96, emp::PUBLIC,
                                            sts, 128);
  emp::ProtocolExecution::prot_exec->reveal(out_bool + 256 + 96, emp::PUBLIC,
                                            stiv, 96);
  emp::finalize_plain_prot();
}

static void DeriveAESSplit() noexcept {
  // This circuit implements the initial IV expansion for AES-CTR mode.
  // Essentially, if you're familiar with the AES-CTR diagram, this computes IV
  // || 0^31 || 1 and outputs shares to both parties. This is important because
  // it takes a 96 bit IV known by both parties and outputs a 128-bit share of
  // the total IV. This is because the IV that's derived in the handshake isn't
  // actually the full IV, but just a portion. The outputs are the output IV
  // (but masked) along with shares of the encryption of the first counter.
  emp::setup_plain_prot(true, "aes_ctr_split.txt");

  // We accept as input a 128 bit key share, 96 bits (the IV), a 128 bit mask
  // (for the output IV), and 128 bit mask (for the output ciphertext).
  constexpr auto input_size = 480;
  std::array<bool, input_size> alice_in, bob_in;
  for (unsigned i = 0; i < input_size; i++) {
    alice_in[i] = rand();
    bob_in[i] = rand();
  }

  emp::block alice_blocks[input_size], bob_blocks[input_size];
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE,
                                          alice_in.data(), input_size);
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_in.data(),
                                          input_size);

  // Recover the key.
  emp::block key[128];
  for (unsigned i = 0; i < 128; i++) {
    key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                        bob_blocks[i]);
  }

  // Recover the IV
  emp::block iv[128];
  for (unsigned i = 0; i < 96; i++) {
    iv[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                       bob_blocks[i]);
  }

  // Fill in the rest with 0s and 1.
  emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);
  emp::block one = emp::CircuitExecution::circ_exec->public_label(true);
  std::fill(iv + 96, iv + 127, zero);
  iv[127] = one;

  // Now we encrypt the IV to produce the first part.
  // The AES circuit needs the key and then the plaintext.
  emp::block input[256];
  memcpy(input, key, 128 * sizeof(emp::block));
  memcpy(input + 128, iv, 128 * sizeof(emp::block));

  // Run the encryption.
  emp::block output[128];
  assert(Util::is_valid_filepath(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt"));
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");
  bf.compute(output, input, input);

  // Now we need to mask the output IV from above.
  emp::block output_iv[128];
  for (unsigned i = 0; i < 128; i++) {
    emp::block tmp = emp::CircuitExecution::circ_exec->xor_gate(
        iv[i], alice_blocks[224 + i]);
    output_iv[i] =
        emp::CircuitExecution::circ_exec->xor_gate(tmp, bob_blocks[224 + i]);
  }

  // And finally mask the output of the encrypted IV too.
  emp::block output_ctx[128];
  for (unsigned i = 0; i < 128; i++) {
    emp::block tmp = emp::CircuitExecution::circ_exec->xor_gate(
        output[i], alice_blocks[352 + i]);
    output_ctx[i] =
        emp::CircuitExecution::circ_exec->xor_gate(tmp, bob_blocks[352 + i]);
  }

  bool out_ctx[128], out_iv[128];
  emp::ProtocolExecution::prot_exec->reveal(out_iv, emp::PUBLIC, output_iv,
                                            128);
  emp::ProtocolExecution::prot_exec->reveal(out_ctx, emp::PUBLIC, output_ctx,
                                            128);
  emp::finalize_plain_prot();
}

static void pclmulqdq(const emp::block *a, const emp::block *b,
                      emp::block *c) noexcept {

  // This is an implementation of the pseudocode found at:
  // https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf
  // Page 8. In particular, this function implements a carryless multiplication
  // over "a" and "b". The function expects `a` and `b` to point to 64 blocks,
  // with `c` pointing to 128 blocks.
  // The algorithm implemented is essentially
  // https://www.felixcloutier.com/x86/pclmulqdq (the "Operation" algorithm).
  assert(a);
  assert(b);
  assert(c);

  emp::block tmp;

  for (unsigned i = 0; i < 64; i++) {
    tmp = emp::CircuitExecution::circ_exec->and_gate(a[0], b[i]);
    for (unsigned j = 1; j <= i; j++) {
      tmp = emp::CircuitExecution::circ_exec->xor_gate(
          tmp, emp::CircuitExecution::circ_exec->and_gate(a[j], b[i - j]));
    }
    c[i] = tmp;
  }

  for (unsigned i = 64; i < 127; i++) {
    tmp = emp::CircuitExecution::circ_exec->public_label(false);
    for (unsigned j = i - 63; j < 64; j++) {
      tmp = emp::CircuitExecution::circ_exec->xor_gate(
          tmp, emp::CircuitExecution::circ_exec->and_gate(a[j], b[i - j]));
    }
    c[i] = tmp;
  }

  c[127] = emp::CircuitExecution::circ_exec->public_label(false);
}

static EmpBlockArray<128> pclmulqdq(const emp::block *const a,
                                    const emp::block *const b) noexcept {
  EmpBlockArray<128> out;
  pclmulqdq(a, b, out.data());
  return out;
}

static void DeriveGCMMultiplicativeSharesNaive() noexcept {
  // This function produces a circuit for a multiplicative share of AES GCM
  // using naive multiplication. This just implements the multiplication
  // algorithm as you'd expect from AES-GCM.
  emp::setup_plain_prot(true, "derive_gcm_mult_shares_naive.txt");
  // We feed in this many mask bits per party.
  static constexpr auto mask_input = 128;
  // And this many key bits per party.
  static constexpr auto key_input = 128;
  // So there's this many input bits in total.
  static constexpr auto input_size = mask_input + key_input;

  const auto zero = emp::CircuitExecution::circ_exec->public_label(false);

  bool alice_input[input_size], bob_input[input_size];
  emp::block alice_blocks[input_size], bob_blocks[input_size];
  for (unsigned i = 0; i < input_size; i++) {
    alice_input[i] = rand();
    bob_input[i] = rand();
  }

  // Feed the input into the garbled circuit.
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_input,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_input,
                                          input_size);

  // Produce the key.
  emp::block key[128];
  for (unsigned i = 0; i < 128; i++) {
    key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                        bob_blocks[i]);
  }

  // The full AES circuit expects key then ciphertext in a single block.
  emp::block circuit_in[256];
  memcpy(circuit_in, key, sizeof(key));
  std::fill(std::begin(circuit_in) + 128, std::end(circuit_in), zero);
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");
  emp::block gcm_key_raw[128];
  bf.compute(gcm_key_raw, circuit_in, circuit_in);

  // Now we multiply through by Bob's share.
  // The multiplication algorithm below
  // comes from the NIST GCM spec
  // (https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
  // page 8, Alg 1).

  auto mult = [zero](emp::block(&z)[128], const emp::block(&x)[128],
                     const emp::block(&y)[128]) {
    // This is a branchless implementation, designed to avoid the use of `ifs`.
    emp::block v[128];
    memcpy(v, x, sizeof(emp::block) * 128);
    emp::block one = emp::CircuitExecution::circ_exec->public_label(true);

    // R is defined in the spec as 111000010000......
    emp::block R[128];
    std::fill(std::begin(R), std::end(R), zero);
    R[0] = one;
    R[1] = one;
    R[2] = one;
    R[7] = one;

    std::fill(std::begin(z), std::end(z), zero);
    emp::block tmp_v[128];
    emp::block tmp_r[128];

    for (unsigned i = 0; i < 128; i++) {
      // NIST says Z = Z \xor V if Y[i] == 1 and Z = Z otherwise.
      // This can be rewritten as Z = Z \xor (V \and arr(Y[i]))
      for (unsigned j = 0; j < 128; j++) {
        tmp_v[j] = emp::CircuitExecution::circ_exec->and_gate(v[j], y[i]);
      }

      for (unsigned j = 0; j < 128; j++) {
        z[j] = emp::CircuitExecution::circ_exec->xor_gate(z[j], tmp_v[j]);
      }

      // NIST also says that if v[127] == 0 then v = v >> 1, else v = v >> 1
      // \xor R Clearly this is equivalent to v = v >> 1 \xor (R \and v[127]).
      for (unsigned j = 0; j < 8; j++) {
        tmp_r[j] = emp::CircuitExecution::circ_exec->and_gate(v[127], R[j]);
      }

      // Rotate to the right by 1.
      std::rotate(std::rbegin(v), std::rbegin(v) + 1, std::rend(v));
      // Zero out the lowest.
      v[0] = zero;

      // Now xor in R.
      for (unsigned j = 0; j < 8; j++) {
        v[j] = emp::CircuitExecution::circ_exec->xor_gate(v[j], tmp_r[j]);
      }
    }

    // Everything is in Z here.
  };

  emp::block prod[128];
  emp::block bob_share[128];
  memcpy(bob_share, bob_blocks + 128, sizeof(bob_share));

  // Multiply through.
  mult(prod, gcm_key_raw, bob_share);

  // Mask against Alice's share.
  for (unsigned i = 0; i < 128; i++) {
    prod[i] = emp::CircuitExecution::circ_exec->xor_gate(prod[i],
                                                         alice_blocks[i + 128]);
  }

  bool output[128];
  emp::ProtocolExecution::prot_exec->reveal(output, emp::PUBLIC, prod, 128);
  emp::finalize_plain_prot();
}

static void gcm_mult(const emp::block (&a)[128], const emp::block (&b)[128],
                     emp::block (&c)[128]) noexcept {

  EmpBlockArray<128> XMMMASK;
  const auto zero = emp::CircuitExecution::circ_exec->public_label(false);
  const auto one = emp::CircuitExecution::circ_exec->public_label(true);
  std::fill(XMMMASK.begin(), XMMMASK.begin() + 32, one);
  std::fill(XMMMASK.begin() + 32, XMMMASK.end(), zero);

  auto tmp3 = pclmulqdq(a, b);
  auto tmp6 = pclmulqdq(a + 64, b + 64);

  auto tmp4 = CircuitSynthesis::shuffle_epi32(a, 78);
  auto tmp5 = CircuitSynthesis::shuffle_epi32(b, 78);
  tmp4 = CircuitSynthesis::xor_si128(tmp4.data(), a);
  tmp5 = CircuitSynthesis::xor_si128(tmp5.data(), b);
  tmp4 = pclmulqdq(tmp4.data(), tmp5.data());
  tmp4 = CircuitSynthesis::xor_si128(tmp4, tmp3);
  tmp4 = CircuitSynthesis::xor_si128(tmp4, tmp6);
  tmp5 = CircuitSynthesis::slli_si128(tmp4, 8);
  tmp4 = CircuitSynthesis::srli_si128(tmp4, 8);
  tmp3 = CircuitSynthesis::xor_si128(tmp3, tmp5);
  tmp6 = CircuitSynthesis::xor_si128(tmp6, tmp4);
  auto tmp7 = CircuitSynthesis::srli_epi32(tmp6, 31);
  auto tmp8 = CircuitSynthesis::srli_epi32(tmp6, 30);
  auto tmp9 = CircuitSynthesis::srli_epi32(tmp6, 25);
  tmp7 = CircuitSynthesis::xor_si128(tmp7, tmp8);
  tmp7 = CircuitSynthesis::xor_si128(tmp7, tmp9);
  tmp8 = CircuitSynthesis::shuffle_epi32(tmp7, 147);
  tmp7 = CircuitSynthesis::and_si128(XMMMASK, tmp8);
  tmp8 = CircuitSynthesis::andnot_si128(XMMMASK, tmp8);
  tmp3 = CircuitSynthesis::xor_si128(tmp3, tmp8);
  tmp6 = CircuitSynthesis::xor_si128(tmp6, tmp7);
  auto tmp10 = CircuitSynthesis::slli_epi32(tmp6, 1);
  tmp3 = CircuitSynthesis::xor_si128(tmp3, tmp10);
  auto tmp11 = CircuitSynthesis::slli_epi32(tmp6, 2);
  tmp3 = CircuitSynthesis::xor_si128(tmp3, tmp11);
  auto tmp12 = CircuitSynthesis::slli_epi32(tmp6, 7);
  tmp3 = CircuitSynthesis::xor_si128(tmp3, tmp12);
  tmp3 = CircuitSynthesis::xor_si128(tmp6, tmp3);
  std::copy(tmp3.begin(), tmp3.end(), &c[0]);
}

static void DeriveGCMMultiplicativeShares() noexcept {
  // This function produces a circuit that generates multiplicative
  // shares of the initial AES GCM share.
  emp::setup_plain_prot(true, "derive_gcm_mult_shares.txt");

  // We feed in this many mask bits per party.
  static constexpr auto mask_input = 128;
  // And this many key bits per party.
  static constexpr auto key_input = 128;
  // So there's this many input bits in total.
  static constexpr auto input_size = mask_input + key_input;

  const auto zero = emp::CircuitExecution::circ_exec->public_label(false);

  bool alice_input[input_size], bob_input[input_size];
  emp::block alice_blocks[input_size], bob_blocks[input_size];
  for (unsigned i = 0; i < input_size; i++) {
    alice_input[i] = rand();
    bob_input[i] = rand();
  }

  // Feed the input into the garbled circuit.
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_input,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_input,
                                          input_size);

  // Produce the key.
  emp::block key[128];
  for (unsigned i = 0; i < 128; i++) {
    key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                        bob_blocks[i]);
  }

  // The full AES circuit expects key then ciphertext in a single block.
  emp::block circuit_in[256];
  memcpy(circuit_in, key, sizeof(key));
  std::fill(std::begin(circuit_in) + 128, std::end(circuit_in), zero);
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");
  emp::block gcm_key_raw[128];
  bf.compute(gcm_key_raw, circuit_in, circuit_in);

  // Now we multiply through by Bob's input mask.
  // This just uses the regular multiplication algorithm over GF(2^128).
  // It turns out this is actually faster than the naive multiplication
  // algorithm from the NIST manual in terms of AND gates.
  // This algorithm is essentially a transcription of the algorithm used in
  // F2128MtA.inl for garbled circuits, which is Algorithm 7 of
  // https://www.intel.com/content/dam/develop/public/us/en/documents/carry-less-multiplication-instruction.pdf,
  // originally. We just adapted it for garbled circuits.
  emp::block a[128], b[128], c[128];
  memcpy(a, gcm_key_raw, sizeof(a));
  memcpy(b, bob_blocks + 128, sizeof(b));
  gcm_mult(a, b, c);

  // Add Alice's 128 bits as a mask.
  for (unsigned i = 0; i < 128; i++) {
    c[i] =
        emp::CircuitExecution::circ_exec->xor_gate(c[i], alice_blocks[128 + i]);
  }

  bool out[128];
  emp::ProtocolExecution::prot_exec->reveal(out, emp::PUBLIC, c, 128);
  emp::finalize_plain_prot();
}

static void DeriveGCMAdditiveShares() noexcept {
  // This function derives additive shares of all GCM shares up to h^1024.
  // This function is not intended to be used: it is only provided to show the
  // circuit costs from the paper.
  emp::setup_plain_prot(true, "derive_gcm_add_shares.txt");
  static constexpr auto mask_input = 131072;
  static constexpr auto key_input = 128;
  static constexpr auto input_size = mask_input + key_input;
  constexpr auto BLOCK = 1024;

  emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);
  bool *alice_in = new bool[input_size];
  bool *bob_in = new bool[input_size];

  // Produce random input data for both.
  for (unsigned i = 0; i < input_size; i++) {
    alice_in[i] = rand();
    bob_in[i] = rand();
  }

  emp::block *alice_blocks = new emp::block[input_size];
  emp::block *bob_blocks = new emp::block[input_size];
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_in,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_in,
                                          input_size);

  // Produce the key.
  emp::block key[128];

  for (unsigned i = 0; i < 128; i++) {
    key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                        bob_blocks[i]);
  }

  // The full AES circuit expects key then ciphertext in a single block.
  emp::block circuit_in[256];
  memcpy(circuit_in, key, sizeof(key));
  std::fill(std::begin(circuit_in) + 128, std::end(circuit_in), zero);
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");
  emp::block gcm_key_raw[128];
  bf.compute(gcm_key_raw, circuit_in, circuit_in);

  // Now produce the rest.
  emp::block middle_results[128][128];
  memset(middle_results, 0, sizeof(emp::block) * 128 * 128);
  for (int i = 0; i < 128; i++) {
    middle_results[0][i] = gcm_key_raw[i];
  }

  for (int i = 1; i < 128; i++) {
    middle_results[i][0] = middle_results[i - 1][127];
    for (int j = 1; j < 128; j++) {
      middle_results[i][j] = middle_results[i - 1][j - 1];
    }

    middle_results[i][7] = emp::CircuitExecution::circ_exec->xor_gate(
        middle_results[i - 1][6], middle_results[i - 1][127]);
    middle_results[i][2] = emp::CircuitExecution::circ_exec->xor_gate(
        middle_results[i - 1][1], middle_results[i - 1][127]);
    middle_results[i][1] = emp::CircuitExecution::circ_exec->xor_gate(
        middle_results[i - 1][0], middle_results[i - 1][127]);
  }

  emp::block *result = new emp::block[128 * BLOCK];
  for (int i = 0; i < 128 * BLOCK; i++) {
    result[i] = zero;
  }

  for (int i = 0; i < 128; i++) {
    result[i] = gcm_key_raw[i];
  }

  for (int b = 1; b < BLOCK; b++) {
    for (int i = 0; i < 128; i++) {
      for (int j = 0; j < 128; j++) {
        emp::block tmp = emp::CircuitExecution::circ_exec->and_gate(
            middle_results[i][j], result[(b - 1) * 128 + i]);
        result[b * 128 + j] = emp::CircuitExecution::circ_exec->xor_gate(
            result[b * 128 + j], tmp);
      }
    }
  }

  emp::block *out = new emp::block[128 * BLOCK];

  CircuitSynthesis::change_endian(EmpBlockNonOwningSpan{result, 128 * BLOCK},
                                  out);

  for (unsigned i = 0; i < 128 * BLOCK; i++) {
    emp::block tmp = emp::CircuitExecution::circ_exec->xor_gate(
        alice_blocks[128 + i], bob_blocks[128 + i]);
    out[i] = emp::CircuitExecution::circ_exec->xor_gate(out[i], tmp);
  }

  bool out_arr[128 * BLOCK];

  emp::ProtocolExecution::prot_exec->reveal(out_arr, emp::PUBLIC, out,
                                            128 * BLOCK);
  delete[] out;
  delete[] result;
  delete[] bob_blocks;
  delete[] alice_blocks;
  delete[] bob_in;
  delete[] alice_in;
  emp::finalize_plain_prot();
}

static emp::block or_gate(emp::block a, emp::block b) noexcept {
  // This function just mimics an OR gate using De Morgan's theorem.
  // I.e a || b = !(!a & !b).
  emp::block inv_a = emp::CircuitExecution::circ_exec->not_gate(a);
  emp::block inv_b = emp::CircuitExecution::circ_exec->not_gate(b);
  return emp::CircuitExecution::circ_exec->not_gate(
      emp::CircuitExecution::circ_exec->and_gate(inv_a, inv_b));
}

template <unsigned int length>
static emp::block equals(const emp::block *const a,
                         const emp::block *const b) noexcept {
  // This function checks whether `a` and `b` are equal by xoring their elements
  // in a pairwise fashion and then ORing each produced bit.
  // This costs `length-1` AND gates (the first one will be optimised away
  // as `out` == 0, so it's just the same as a[i]^b[i].
  assert(a);
  assert(b);
  emp::block out = emp::CircuitExecution::circ_exec->public_label(false);
  for (unsigned i = 0; i < length; i++) {
    out = or_gate(out, emp::CircuitExecution::circ_exec->xor_gate(a[i], b[i]));
  }

  // Make the output bit 1 if the answer is 0, 0 otherwise.
  return emp::CircuitExecution::circ_exec->not_gate(out);
}

static void DeriveGCMTag() {
  emp::setup_plain_prot(true, "derive_gcm_tag.txt");
  // This circuit derives the GCM tag from each party. Concretely, each party
  // feeds in a key share, a tag share, an IV copy. Moreover, P1 feeds in a 128
  // bit mask, whereas P2 feeds in 256 bits of unused values. The values are
  // also fed in as written (i.e the key share is in the first 128 bits, then
  // the tag, then the IV etc).
  constexpr auto input_size = 128 + 128 + 128 + 128;

  bool alice_in[input_size], bob_in[input_size];
  for (unsigned i = 0; i < input_size; i++) {
    alice_in[i] = rand();
    bob_in[i] = rand();
  }

  emp::block alice_blocks[input_size], bob_blocks[input_size];
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_in,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_in,
                                          input_size);

  // Recover the key and IV.
  emp::block key_and_iv[256];
  for (unsigned i = 0; i < 128; i++) {
    key_and_iv[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                               bob_blocks[i]);
  }

  // Just copy over Alice's IV for now.
  memcpy(key_and_iv + 128, alice_blocks + 128, sizeof(emp::block) * 128);
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");

  emp::block output[128];
  bf.compute(output, key_and_iv, key_and_iv);

  // Now we can produce the tag shares too. We just xor against the output
  // directly.
  for (unsigned i = 0; i < 128; i++) {
    output[i] = emp::CircuitExecution::circ_exec->xor_gate(
        output[i], emp::CircuitExecution::circ_exec->xor_gate(
                       alice_blocks[i + 256], bob_blocks[i + 256]));
  }

  // Now we check if the IVs were the same.
  const auto were_same = equals<128>(alice_blocks + 128, bob_blocks + 128);

  // Make that into a mask block.
  emp::block mask[128];
  std::fill(std::begin(mask), std::end(mask), were_same);

  // Now mask out.
  for (unsigned i = 0; i < 128; i++) {
    output[i] = emp::CircuitExecution::circ_exec->and_gate(mask[i], output[i]);
  }

  // Reveal the bit. To make life easier from an implementation perspective,
  // we actually pack it into 8 entries.
  bool b[8];
  emp::ProtocolExecution::prot_exec->reveal(b, emp::PUBLIC, mask, 8);

  // Now mask the tag against alice's mask.
  for (unsigned i = 0; i < 128; i++) {
    output[i] = emp::CircuitExecution::circ_exec->xor_gate(
        output[i], alice_blocks[384 + i]);
  }

  // Reveal them to Alice.
  bool tag[128];
  emp::ProtocolExecution::prot_exec->reveal(tag, emp::ALICE, output, 128);
  emp::finalize_plain_prot();
}

static void DeriveGCMVerify() {
  emp::setup_plain_prot(true, "derive_gcm_verify.txt");
  // This is essentially the same setup as with the tagging, but
  // here we also take the server tag from both parties.
  // That, and there's no mask on the output: we just only output one bit.
  constexpr auto input_size = 128 + 128 + 128 + 128;

  bool alice_input[input_size], bob_input[input_size];
  for (unsigned i = 0; i < input_size; i++) {
    alice_input[i] = rand();
    bob_input[i] = rand();
  }

  emp::block alice_blocks[input_size], bob_blocks[input_size];
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_input,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_input,
                                          input_size);

  // Recover the key and IV.
  emp::block key_and_iv[256];
  for (unsigned i = 0; i < 128; i++) {
    key_and_iv[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                               bob_blocks[i]);
  }

  // Just copy over Alice's IV for now.
  memcpy(key_and_iv + 128, alice_blocks + 128, sizeof(emp::block) * 128);
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");

  emp::block output[128];
  bf.compute(output, key_and_iv, key_and_iv);

  // Now we can produce the tag shares too. We just xor against the output
  // directly.
  for (unsigned i = 0; i < 128; i++) {
    output[i] = emp::CircuitExecution::circ_exec->xor_gate(
        output[i], emp::CircuitExecution::circ_exec->xor_gate(
                       alice_blocks[i + 256], bob_blocks[i + 256]));
  }

  // Now we check if the IVs were the same.
  const auto were_ivs_same = equals<128>(alice_blocks + 128, bob_blocks + 128);

  // And we also do the same for the server tags.
  const auto were_tags_same = equals<128>(alice_blocks + 384, bob_blocks + 384);

  // Combine into a single bit.
  const auto did_either_cheat = or_gate(were_ivs_same, were_tags_same);

  // Now check if the tags were the same. We just use one of the input tags.
  // We also mask against the cheating information, because otherwise the output
  // is unreliable.
  const auto tag_verify = emp::CircuitExecution::circ_exec->and_gate(
      equals<128>(output, alice_blocks + 384), did_either_cheat);

  // Now we pad out the tag_verify to 8 bits, and the same with
  // did_either_cheat.
  emp::block tv[8], pc[8];
  std::fill(std::begin(tv), std::end(tv), tag_verify);
  std::fill(std::begin(pc), std::end(pc), did_either_cheat);

  bool tag_vf[8], party_cheat[8];
  emp::ProtocolExecution::prot_exec->reveal(tag_vf, emp::PUBLIC, tv, 8);
  emp::ProtocolExecution::prot_exec->reveal(party_cheat, emp::PUBLIC, pc, 8);
  emp::finalize_plain_prot();
}

static void DeriveCTXCommitments() {
  emp::setup_plain_prot(true, "derive_ctx_commitments.txt");

  // This circuit derives commitments to a particular AES CTR mode "block key".
  // Both parties feed in shares of an IV and their key, learning shares of K_I
  // = Enc(K, IV + I). Note that this assumes that the prover has already
  // committed to their key shares!

  // In this model, the prover supplies the IV, their key share, and the output
  // mask. The verifier supplies the IV and their key share, with 128 unused
  // wires.

  constexpr auto input_size = 128 + 128 + 128;

  bool alice_input[input_size];
  bool bob_input[input_size];

  for (unsigned i = 0; i < input_size; i++) {
    alice_input[i] = rand();
    bob_input[i] = rand();
  }

  emp::block alice_blocks[input_size], bob_blocks[input_size];
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_input,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_input,
                                          input_size);

  // Recover the IV and the key.
  emp::block IV[128], key[128];
  for (unsigned i = 0; i < 128; i++) {
    IV[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                       bob_blocks[i]);
    key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i + 128],
                                                        bob_blocks[i + 128]);
  }

  // Now we can do the full encryption.
  // The full AES circuit expects key then ciphertext in a single block.
  emp::block circuit_in[256];
  memcpy(circuit_in, key, sizeof(key));
  memcpy(circuit_in + 128, IV, sizeof(IV));
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");

  emp::block output[128];
  bf.compute(output, circuit_in, circuit_in);

  // Check the IVs are the same.
  const auto were_same = equals<128>(alice_blocks, bob_blocks);

  // Produce the additive shares. This is just done by XORING
  // the produced ciphertext with the mask
  for (unsigned i = 0; i < 128; i++) {
    output[i] = emp::CircuitExecution::circ_exec->xor_gate(
        output[i], alice_blocks[i + 256]);
    // Mask against the output.
    output[i] =
        emp::CircuitExecution::circ_exec->and_gate(output[i], were_same);
  }

  bool output_b[128];
  bool output_same[8];
  emp::block same_arr[8];
  std::fill(std::begin(same_arr), std::end(same_arr), were_same);
  emp::ProtocolExecution::prot_exec->reveal(output_b, emp::PUBLIC, output, 128);
  emp::ProtocolExecution::prot_exec->reveal(output_same, emp::PUBLIC, same_arr,
                                            8);
  emp::finalize_plain_prot();
}

static void DeriveAESJoint() noexcept {
  // This circuit accepts a 128 bit plaintext block, a 128 bit key share from
  // each party, and a 128 bit IV. Each party learns the full output. Note
  // that if the IVs do not match the output is all 0s. Also, only Alice
  // supplies an input plaintext e.g Bob's first 128 bits are unused.
  emp::setup_plain_prot(true, "aes_ctr_joint.txt");
  constexpr auto input_size = 384;
  std::array<bool, input_size> alice_in, bob_in;
  for (unsigned i = 0; i < input_size; i++) {
    alice_in[i] = rand();
    bob_in[i] = rand();
  }

  emp::block alice_blocks[input_size], bob_blocks[input_size];
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE,
                                          alice_in.data(), input_size);
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_in.data(),
                                          input_size);

  // Recover the key.
  emp::block key_and_iv[256];
  for (unsigned i = 0; i < 128; i++) {
    key_and_iv[i] = emp::CircuitExecution::circ_exec->xor_gate(
        alice_blocks[i + 128], bob_blocks[i + 128]);
  }

  // For now just take Alice's IV.
  memcpy(key_and_iv + 128, alice_blocks + 256, sizeof(emp::block) * 128);
  // Run the encryption.
  emp::block output[128];
  assert(Util::is_valid_filepath(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt"));
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");
  bf.compute(output, key_and_iv, key_and_iv);

  // Now we need to check that the IVs were the same.
  emp::block were_ivs_same = equals<128>(alice_blocks + 256, bob_blocks + 256);

  emp::block mask[128];
  std::fill(std::begin(mask), std::end(mask), were_ivs_same);

  // Do the XOR with the plaintext.
  for (unsigned i = 0; i < 128; i++) {
    output[i] =
        emp::CircuitExecution::circ_exec->xor_gate(output[i], alice_blocks[i]);
  }

  // Mask out the output.
  for (unsigned i = 0; i < 128; i++) {
    output[i] = emp::CircuitExecution::circ_exec->and_gate(output[i], mask[i]);
  }

  // Now reveal if they cheated. Again, pad to a multiple of 8.
  bool were_sameb[8];
  bool ctxt[128];
  emp::ProtocolExecution::prot_exec->reveal(were_sameb, emp::PUBLIC, mask, 8);
  emp::ProtocolExecution::prot_exec->reveal(ctxt, emp::PUBLIC, output, 128);
  emp::finalize_plain_prot();
}

static void DeriveRotateKey() {
  emp::setup_plain_prot(true, "derive_rotate_key.txt");

  constexpr auto input_size = 384;
  std::array<bool, input_size> alice_in, bob_in;
  for (unsigned i = 0; i < input_size; i++) {
    alice_in[i] = rand();
    bob_in[i] = rand();
  }

  emp::block alice_blocks[input_size], bob_blocks[input_size];
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE,
                                          alice_in.data(), input_size);
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_in.data(),
                                          input_size);

  emp::block secret[256];
  memcpy(secret, alice_blocks, sizeof(emp::block) * 128);
  memcpy(secret + 128, bob_blocks, sizeof(emp::block) * 128);

  emp::block hash[256];
  memcpy(hash, alice_blocks + 128, sizeof(hash));

  emp::block derived[128];

  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{secret, 256}, "traffic upd",
      EmpBlockNonOwningSpan{hash, 256}, derived, 16);

  for (unsigned i = 0; i < 128; i++) {
    derived[i] = emp::CircuitExecution::circ_exec->xor_gate(
        derived[i], bob_blocks[128 + i]);
  }

  bool key[128];
  emp::ProtocolExecution::prot_exec->reveal(key, emp::PUBLIC, derived, 128);
  emp::finalize_plain_prot();
}

template <unsigned size> static void DeriveAESEnc() {
  // This function derives batched AES GCM encryptions
  // i.e it produces circuits for encrypting fixed size requests.
  // `size` inputs the number of AES-GCM blocks to encrypt. Each block is taken
  // to be 128 bits. Everything (including incrementing the IVs) is done
  // internally.
  emp::setup_plain_prot(true, "aes_ctr_batch_" + std::to_string(size) + ".txt");
  constexpr auto input_size = 256 + size * 128;
  std::array<bool, input_size> alice_in, bob_in;
  for (unsigned i = 0; i < input_size; i++) {
    alice_in[i] = rand();
    bob_in[i] = rand();
  }

  emp::block alice_blocks[input_size], bob_blocks[input_size];
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE,
                                          alice_in.data(), input_size);
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_in.data(),
                                          input_size);

  // Check that the IVs were the same.
  // Now we need to check that the IVs were the same.
  emp::block were_ivs_same = equals<128>(alice_blocks + 128, bob_blocks + 128);

  // We'll recover the IV for later use. For now we'll just use Alice's.
  emp::block IV[128];
  memcpy(IV, alice_blocks + 128, sizeof(IV));

  // Recover the key.
  emp::block cipher_in[256];
  for (unsigned i = 0; i < 128; i++) {
    cipher_in[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                              bob_blocks[i]);
  }

  emp::block cipher_out[128];

  // Load the circuit.
  assert(Util::is_valid_filepath(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt"));
  emp::BristolFormat aes(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");

  assert(Util::is_valid_filepath("../2pc/vhdl/Inc128.txt"));
  emp::BristolFashion inc("../2pc/vhdl/Inc128.txt");

  bool were_same_b[8];
  emp::block same[8];
  std::fill(std::begin(same), std::end(same), were_ivs_same);
  emp::ProtocolExecution::prot_exec->reveal(were_same_b, emp::PUBLIC, same, 8);

  emp::block ctxt[128];
  bool *ctxt_out = new bool[size * 128];

  // Now do the encryption. Each encryption is done by first adding 1 to the IV
  // and then using that as input to the circuit.
  for (unsigned i = 0; i < size; i++) {
    inc.compute(cipher_in + 128, IV);
    memcpy(IV, cipher_in + 128, sizeof(IV));
    aes.compute(cipher_out, cipher_in, cipher_in);
    for (unsigned j = 0; j < 128; j++) {
      ctxt[j] = emp::CircuitExecution::circ_exec->xor_gate(
          cipher_out[j], alice_blocks[(i * 128) + j + 256]);
    }

    emp::ProtocolExecution::prot_exec->reveal(ctxt_out + 128 * i, emp::PUBLIC,
                                              ctxt, 128);
  }

  delete[] ctxt_out;
  emp::finalize_plain_prot();
}

// These functions are just to make calling the various templated functions
// easier.

static void DeriveHS256() { DeriveHS<256>(); }
static void DeriveHS384() { DeriveHS<384>(); }
static void DeriveHS521() { DeriveHS<521>(); }

static void DeriveCombined256() { ProduceCombinedCircuit<256>(); }
static void DeriveCombined384() { ProduceCombinedCircuit<384>(); }
static void DeriveCombinedTS() { ProduceCombinedTrafficCircuits(); }

template <TypeOfDerivation mode>
static void dispatch_to_derive_session_secrets() {
  DeriveSessionSecrets<mode, true>();
  DeriveSessionSecrets<mode, false>();
}

static void DeriveCHTSATS() {
  dispatch_to_derive_session_secrets<TypeOfDerivation::CLIENT_HTS>();
  dispatch_to_derive_session_secrets<TypeOfDerivation::SERVER_HTS>();
  dispatch_to_derive_session_secrets<TypeOfDerivation::SATS>();
  dispatch_to_derive_session_secrets<TypeOfDerivation::CATS>();
  dispatch_to_derive_session_secrets<TypeOfDerivation::EMS>();
}

template <TypeOfDerivation mode> static void dispatch_to_derive_key_or_iv() {
  // We call the testing version of the function first: if it works, we call
  // the version that produces the actual results.
  DeriveIVOrKey<mode, true>();
  DeriveIVOrKey<mode, false>();
}

static void DeriveTrafficKeyAndIVs() {
  dispatch_to_derive_key_or_iv<TypeOfDerivation::CLIENT_HANDSHAKE_IV>();
  dispatch_to_derive_key_or_iv<TypeOfDerivation::CLIENT_TRAFFIC_IV>();
  dispatch_to_derive_key_or_iv<TypeOfDerivation::SERVER_HANDSHAKE_IV>();
  dispatch_to_derive_key_or_iv<TypeOfDerivation::SERVER_TRAFFIC_IV>();
  dispatch_to_derive_key_or_iv<TypeOfDerivation::CLIENT_HANDSHAKE_KEY>();
  dispatch_to_derive_key_or_iv<TypeOfDerivation::CLIENT_TRAFFIC_KEY>();
  dispatch_to_derive_key_or_iv<TypeOfDerivation::SERVER_HANDSHAKE_KEY>();
  dispatch_to_derive_key_or_iv<TypeOfDerivation::SERVER_TRAFFIC_KEY>();
}

static void DeriveMSAndDHS() {
  DeriveDHS<true>();
  DeriveDHS<false>();
  DeriveMS<true>();
  DeriveMS<false>();
}

int main(int, char **) {
  DeriveHS256();
  DeriveHS384();
  DeriveHS521();
  DeriveCHTSATS();
  DeriveMSAndDHS();
  DeriveTrafficKeyAndIVs();
  DeriveAESEncryption();
  DeriveGCMMultiplicativeSharesNaive();
  DeriveAESEnc<16>();
  DeriveAESEnc<32>();
  DeriveAESEnc<64>();
  DeriveAESEnc<128>();
  DeriveRotateKey();
  DeriveCombined256();
  DeriveCombined384();
  DeriveCombinedTS();
  DeriveGCMMultiplicativeShares();
  DeriveCTXCommitments();
  DeriveAESJoint();
  DeriveGCMTag();
  DeriveGCMVerify();
}

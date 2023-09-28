#ifndef INCLUDED_CIRCUITSYNTHESIS_HPP
#define INCLUDED_CIRCUITSYNTHESIS_HPP

#include "../mta/EmpBlockArray.hpp" // Needed for sane use of emp::block
#include "../mta/EmpBlockSpan.hpp"  // Needed for sane use of emp::block
#include "openssl/base.h"           // Needed for bssl::Array etc
#include "ssl/internal.h"           // Needed for other bssl types.
#include <emp-tool/emp-tool.h>      // Needed for circuit building.

/**
   CircuitSynthesis. This header file contains various implementation
   details for circuit synthesis using EMP. This namespace is primarily
   intended to be used to generate circuits in an offline sense: namely,
   this namespace (and the functions that are provided herein) should be used
   outside of TLS attestation. Instead, this should take place during an offline
phase.

   Note that most of the code in this namespace was initially from:

   Weikeng Chen, Ryan Deng, and Raluca Ada Popa,
   N-for-1 Auth: N-wise Decentralized Authentication via One Authentication
   ohttps://eprint.iacr.org/2021/342

   https://github.com/n-for-1-auth/circuits/blob/cab09737ee7a76ead1cefa43860c949e8d7b16df/generator/generate_handshake_circuits.cpp,
accessed on 17th August 2022.

   In some places we have changed this code to make it slightly more idiomatic
   C++, or to take better advantage of the C++ standard library. In addition to
this, we have also added a series of tests (in CircuitSynthesis.t.cpp). To make
sure that this code does not differ too strongly from n-for-1-auth, our tests
also contain known answer tests with values that were, again, taken from
n-for-1-auth.


@remarks This namespace requires C++17 to compile properly. This is because
C++17 introduced the notion of inline constexpr variables, which allows us to
initialise constexpr variables inside namespaces at header file scope. See the
following reference for more (note that this is the very first item explained):

Nicolai Josuttis, C++17 - The Best Features,
ACCU 2018, https://youtu.be/e2ZQyYr0Oi0


@remarks Note that most of the functions in this namespace require you to call
the emp::setup_plain_prot() function beforehand. This is because emp requires
various globals to be set-up before circuit evaluation can occur. Similarly,
upon finishing it is wise to call emp::finalize_plain_prot(). The tests for each
function show for which functions this is necessary.
**/
namespace CircuitSynthesis {

/**
   AES128_FULL_FILEPATH. This contains the filepath for the AES 128 Full
   ciruit from n-for-1-auth.
**/
inline constexpr auto AES128_FULL_FILEPATH =
    "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt";

/**
   SHA256_FILEPATH. This contains the filepath for the SHA256 Bristol Format
   circuit. Here we use the SHA-256-multiblock-aligned circuit from
 n-for-1-auth.
 **/
inline constexpr auto SHA256_FILEPATH =
    "../emp-tool/emp-tool/circuits/files/bristol_format/"
    "sha-256-multiblock-aligned.txt";

/**
   MA_256_FILEPATH. This contains the filepath for the ModAdd256 Bristol Fashion
   circuit. Here we use the ModAdd256 circuit made for this project.
**/
inline constexpr auto MA_256_FILEPATH = "../2pc/vhdl/ModAdd256.txt";
/**
 MA_256_FILEPATH. This contains the filepath for the ModAdd384 Bristol Fashion
 circuit. Here we use the ModAdd384 circuit made for this project.
**/
inline constexpr auto MA_384_FILEPATH = "../2pc/vhdl/ModAdd384.txt";
/**
 MA_521_FILEPATH. This contains the filepath for the ModAdd521 Bristol Fashion
 circuit. Here we use the ModAdd521 circuit made for this project.
**/
inline constexpr auto MA_521_FILEPATH = "../2pc/vhdl/ModAdd521.txt";

/**
   reverse_bytes. This function inplace reverses the entries in `blocks`.
   Specifically, this function does the following:

   blocks[0] = blocks[length - 1];
   blocks[1] = blocks[length - 2];
   ...
   blocks[i] = blocks[length - i - 1];
   ...
   blocks[length - 1] = blocks[0];

   This function does not throw.

   @snippet CircuitSynthesis.t.cpp CircuitSynthesisReverseBytes
   @param[in] blocks: the array of blocks to reverse.
**/
void reverse_bytes(EmpBlockNonOwningSpan blocks) noexcept;
/**
   reverse_bytes. This function inplace reverses the entries in `blocks`.
   Specifically, this function does the following:

   blocks[0] = blocks[length - 1];
   blocks[1] = blocks[length - 2];
   ...
   blocks[i] = blocks[length - i - 1];
   ...
   blocks[length - 1] = blocks[0];

   This function does not throw.

   @snippet CircuitSynthesis.t.cpp CircuitSynthesisReverseBytes
   @param[in] blocks: the array of blocks to reverse.
**/
void reverse_bytes(EmpBlockOwningSpan &blocks) noexcept;

/**
   change_endian. This function takes the `input` block and
reverses the endianness of each 8-block "chunk", storing the
result in `output`. This function does not throw.

   @snippet CircuitSynthesis.t.cpp
CircuitSynthesisChangeEndian
   @param[in] input: the input span of blocks. Must contain a
non-null pointer.
   @param[out] output: the location to write the reversed
`input`. The caller must ensure that `output` has sufficient
space to hold the reversed version of `input`.
   @remarks Note that input.size() % 8 == 0 is a pre-condition.
**/
void change_endian(const EmpBlockOwningSpan &input,
                   emp::block *const out) noexcept;

/**
   change_endian. This function takes the `input` block and
reverses the endianness of each 8-block "chunk", storing the
result in `output`. This function does not throw.

   @snippet CircuitSynthesis.t.cpp
CircuitSynthesisChangeEndian
   @param[in] input: the input span of blocks. Must contain a
non-null pointer.
   @param[out] output: the location to write the reversed
`input`. The caller must ensure that `output` has sufficient
space to hold the reversed version of `input`.
   @remarks Note that input.size() % 8 == 0 is a pre-condition.
**/
void change_endian(const EmpBlockNonOwningSpan input,
                   emp::block *const out) noexcept;

/**
   get_padded_len. This function rounds `len` up to the
nearest multiple of 512. This function does not throw.
   @snippet CircuitSynthesis.t.cppp
CircuitSynthesisGetPaddedLen
   @param[in] len: the length to round up.
   @return `len` rounded up to the nearest multiple of 512.
**/
template <typename T> constexpr T get_padded_len(const T len) noexcept;

/**
   get_K. This function finds `K` such that `len + 1 + K +
64` is a multiple of 512. This function does not throw.
   @snippet CircuitSynthesis.t.cpp CircuitSynthesisGetK
   @param[in] len: the length to round up.
   @return `K` such that `len + 1 + K + 64` is a multiple of
512.
**/
template <typename T> constexpr T get_K(const T len) noexcept;

/**
   padding. This function takes the `input` and pads it into
the `output`. In particular, this function produces the
following output:

   1. `output[0 : input.size - 1] = input`;
   2. `output[input.size] = 1`.
   3. `output[input.size + 1 + K + 48] = 0`, where `K` is
get_K(len).
   4. `output[input.size + 1 + K + 48 : len + 1 + K + 64] =
BIG_ENDIAN_BITS(input.size)`.

   This function does not throw.

   @snippet CircuitSynthesis.t.cpp CircuitSynthesisPadding
   @param[in] input: the input block span. This cannot contain a null pointer.
   @param[out] output: the output block array. This cannot be
null and must point to an array that contains at least input.size() +
1 + K + 64 entries.
**/
void padding(const EmpBlockOwningSpan &input,
             emp::block *const output) noexcept;

/**
   produce_digest_bits. This function accepts as input an array of blocks
(`digest_bits`) and writes the block form of the SHA-256 digest bits to the
array. The digest bits are constants that are specified in the SHA-256 standard
and provided by existing TLS libraries.

   For the sake of this function, we took the constants from BoringSSL: however,
   these constants should be the same in all major TLS libraries.

   This function does not throw.
   @param[out] blocks: the location to write the digest bits. Must be non-null.
**/
void produce_digest_bits(emp::block *const digest_bits) noexcept;

/**
   change_endian_four. This function accepts as input an array of blocks
(`input`) and applies a permutation to each 32-entry block of `input`, storing
the result in `output`. In particular, the output format is as follows:

   output[0:7, 8:15, 16:23, 24:31] = input[24:31, 16:23, 8:15, 0:7].

   This function is also provided in n-for-1-auth: we simply extract it to make
it easier to test. This function does not throw.

   Note that this function only processes the first 256 entries of the `input`.
   We also therefore require that `input` points to at least 256 blocks.
Similarly, `output` should contain at least 256 blocks for output.

   @snippet CircuitSynthesis.t.cpp CircuitSynthesisEndianFour
   @param[in] input: the input blocks to be permuted. Must be non-null.
   @param[out] output: the location to write the permuted blocks. Must be
non-null.
   @remarks input and output should not overlap.
**/
void change_endian_four(const emp::block *const input,
                        emp::block *const output) noexcept;

/**
   sha256. This function applies the SHA-256 hash function to the blocks in
   `input` and writes the resulting bytes to `output`. This function does not
    throw. Note that `input` does not have to be padded appropriately: this
function applies the appropriate padding.

@snippet CircuitSynthesis.t.cpp CircuitSynthesisSha256
@param[in] input: the input blocks to hash. Must have a valid `data` member.
@param[out] output: the location to write the hashed blocks. Must be non-null.
@remarks input and output should not overlap.
**/
void sha256(const EmpBlockOwningSpan &input, emp::block *const output) noexcept;
/**
   sha256. This function applies the SHA-256 hash function to the blocks in
   `input` and writes the resulting bytes to `output`. This function does not
    throw. Note that `input` does not have to be padded appropriately: this
function applies the appropriate padding.

@snippet CircuitSynthesis.t.cpp CircuitSynthesisSha256
@param[in] input: the input blocks to hash. Must have a valid `data` member.
@param[out] output: the location to write the hashed blocks. Must be non-null.
@remarks input and output should not overlap.
**/
void sha256(EmpBlockNonOwningSpan input, emp::block *const output) noexcept;

/**
   hmac. This function computes the hmac of `data` with key `key`, writing the
result to `output`. This function uses the sha256 routine internally to
produce the relevant outputs.

@snippet CircuitSynthesis.t.cpp CircuitSynthesisHmac
@param[in] key: the key for the hmac.
@param[in] data: the data input for the hmac.
@param[out] output: the location to store the output. Must be non-null and point
to at least 256 entries.
**/
void hmac(const EmpBlockOwningSpan &key, const EmpBlockOwningSpan &data,
          emp::block *const output) noexcept;

/**
   hmac. This function computes the hmac of `data` with key `key`, writing the
result to `output`. This function uses the sha256 routine internally to
produce the relevant outputs.

@snippet CircuitSynthesis.t.cpp CircuitSynthesisHmac
@param[in] key: the key for the hmac.
@param[in] data: the data input for the hmac.
@param[out] output: the location to store the output. Must be non-null and point
to at least 256 entries.
**/
void hmac(const EmpBlockNonOwningSpan key, const EmpBlockNonOwningSpan data,
          emp::block *const output) noexcept;

/**
   hkdf_extract. This function implements the HKDF-Extract function used inside
TLS. In particular, using the notation from RFC 5869, this function accepts a
`salt` as input alongside some input keying material (`ikm`) and produces:

   output = HKDF-Extract(salt, ikm)

psuedorandom key as output. For the sake of this implementation, the output is
always 256 bits in size.

This function does not throw.
@snippet CircuitSynthesis.t.cpp CircuitSynthesisHKDFExtract
@param[in] salt: the salt for the hkdf.
@param[in] ikm: the input keying material for the hkdf.
@param[out] output: the location to store the output block. Cannot be null. Must
point to an array of (at least) 256 blocks.
**/
void hkdf_extract(const EmpBlockOwningSpan &salt, const EmpBlockOwningSpan &ikm,
                  emp::block *output) noexcept;
/**
 hkdf_extract. This function implements the HKDF-Extract function used inside
TLS. In particular, using the notation from RFC 5869, this function accepts a
`salt` as input alongside some input keying material (`ikm`) and produces:

   output = HKDF-Extract(salt, ikm)

For the sake of this implementation, the output is always 256 bits in size.

This function does not throw.
@snippet CircuitSynthesis.t.cpp CircuitSynthesisHKDFExtract
@param[in] salt: the salt for the hkdf.
@param[in] ikm: the input keying material for the hkdf.
@param[out] output: the location to store the output block. Cannot be null. Must
point to an array of (at least) 256 blocks.
**/
void hkdf_extract(const EmpBlockNonOwningSpan &salt,
                  const EmpBlockNonOwningSpan &ikm,
                  emp::block *output) noexcept;

/**
   hkdf_expand. This function implements the HKDF.Expand function used inside
TLS. In particular, using the notation from RFC 5869, this function accepts as
input a `key`, alongside some `info` and the output length of the key
(`output_byte_len`) and produces:

   output = HKDF-Expand(key, info, output_byte_len)

This function does not throw.
@param[in] key: the keying material to pass into HKDF-Expand.
@param[in] info: the info material to pass into HKDF-Expand.
@param[out] out: the location to store the output blocks. Cannot be null.
Must point to an array of (at least) `output_byte_len` blocks.
@param[in] output_byte_len: the number of output bytes to generate.
**/
void hkdf_expand(const EmpBlockOwningSpan &key, const EmpBlockOwningSpan &info,
                 emp::block *const output,
                 const unsigned output_byte_len) noexcept;
/**
   hkdf_expand. This function implements the HKDF.Expand function used inside
TLS. In particular, using the notation from RFC 5869, this function accepts as
input a `key`, alongside some `info` and the output length of the key
(`output_byte_len`) and produces:

   output = HKDF-Expand(key, info, output_byte_len)

This function does not throw.
@param[in] key: the keying material to pass into HKDF-Expand.
@param[in] info: the info material to pass into HKDF-Expand.
@param[out] out: the location to store the output blocks. Cannot be null.
Must point to an array of (at least) `output_byte_len` blocks.
@param[in] output_byte_len: the number of output bytes to generate.
**/
void hkdf_expand(const EmpBlockNonOwningSpan key,
                 const EmpBlockNonOwningSpan info, emp::block *const output,
                 const unsigned output_byte_len) noexcept;

/**
   hkdf_expand_label. This function accepts as input keying material (`key`),
   a `label`, some contextual information (`context`) and calls the HKDF-Expand
   function on those inputs, storing the result in `output`. More precisely,
   this function computes:

   long_label = "tls13 " + label
   context_info = output_byte_len || len(long_label) || long_label || context
   output = HKDF-Expand(key, context_info, output_byte_len)

   Where || denotes concatenation.

   This function does not throw.
   @snippet CircuitSynthesis.t.cpp CircuitSynthesisHKDFExtractLabel
   @param[in] key: the input keying material to expand.
   @param[in] label: the label to expand.
   @param[in] context: the context to expand. This data should be stored in Big
Endian format.
   @param[out] output: the location to write the output. Cannot be null. Must
point to an array of (at least) output_byte_len blocks.
   @param[in] output_byte_len: the number of output bytes to write.
**/
void hkdf_expand_label(const EmpBlockOwningSpan &key, const std::string &label,
                       const EmpBlockOwningSpan &context,
                       emp::block *const output, const unsigned output_byte_len,
                       const bool force = false) noexcept;
/**
   hkdf_expand_label. This function accepts as input keying material (`key`),
   a `label`, some contextual information (`context`) and calls the HKDF-Expand
   function on those inputs, storing the result in `output`. More precisely,
   this function computes:

   long_label = "tls13 " + label
   context_info = output_byte_len || len(long_label) || long_label || context
   output = HKDF-Expand(key, context_info, output_byte_len)

   Where || denotes concatenation.

   This function does not throw.
   @snippet CircuitSynthesis.t.cpp CircuitSynthesisHKDFExtractLabel
   @param[in] key: the input keying material to expand.
   @param[in] label: the label to expand.
   @param[in] context: the context to expand.
   @param[out] output: the location to write the output. Cannot be null. Must
point to an array of (at least) output_byte_len blocks.
   @param[in] output_byte_len: the number of output bytes to write.
**/
void hkdf_expand_label(const EmpBlockNonOwningSpan key,
                       const std::string &label,
                       const EmpBlockNonOwningSpan context,
                       emp::block *const output, const unsigned output_byte_len,
                       const bool force = false) noexcept;

/**
   convert_bssl_array_to_emp_span. This function accepts a serialised bssl
bignum `a` and converts it into a span of emp::blocks. In particular, this
function takes `a` (a big endian serialised representation) and represents each
bit of `a` as an emp::block. Note that this function returns a span that is
little-endian: this is because our addition circuits expect little endian
numbers, and this function is meant to be used in conjunction with those
circuits exclusively.

   This function does not throw.
   @snippet CircuitSynthesis.t.cpp CircuitSynthesisBA2ES
   @param[in] a: the array to convert.
   @return an EmpBlockOwningSpan of size `a.size() * CHAR_BIT`.
**/
EmpBlockOwningSpan
convert_bssl_array_to_emp_span(const bssl::Array<uint8_t> &a) noexcept;

/**
   add_two_mod_p. This function accepts three serialised bignums `a`, `b`, `p`,
in little-endian format and computes `a + b (mod p)` using an addition circuit,
writing the result into `out`.

   Note that this function has several pre-conditions:
   1. All input pointers must be non-null.
   2. `a`, `b`, `p` must not overlap.
   3. `a`, `b`, `p` and `out` should each point to an array of at least `length`
entries.
   4. `a` < `p`.
   5. `b` < `p`.
   6. `a`, `b`, `p` should all be `length` bits in length.

   If any of these conditions are not satisfied then the behaviour of this
function is undefined.

   This function does not throw.

   @snippet CircuitSynthesis.t.cpp CircuitSynthesisAddTwoModP
   @param[in] a: a serialised bignum.
   @param[in] b: a serialised bignum.
   @param[in] p: the modulus to use.
   @param[out] out: the location to write the result.
   @param[in] length: the bit length of the entries. Must be one of 256, 384 or
521.
**/
void add_two_mod_p(const bool *const a, const bool *const b,
                   const bool *const p, emp::block *const out,
                   const unsigned length) noexcept;

/**
   add_two_mod_p. This function accepts three serialised bignums `a`, `b`, `p`,
in little-endian format and computes `a + b (mod p)` using an addition circuit,
writing the result into `out`.

   Note that this function has several pre-conditions:
   1. `a`, `b`, `p` and `out` should each contain exactly `length` entries.
   2. `a` < `p`.
   3. `b` < `p`.


   If any of these conditions are not satisfied then the behaviour of this
function is undefined.

   This function does not throw.

   @snippet CircuitSynthesis.t.cpp CircuitSynthesisAddTwoModP
   @param[in] a: a serialised bignum as EmpBlocks.
   @param[in] b: a serialised bignum as EmpBlocks.
   @param[in] p: the modulus to use.
   @param[out] out: the location to write the result.
   @param[in] length: the bit length of the entries. Must be one of 256, 384 or
521.
**/
void add_two_mod_p(const EmpBlockOwningSpan &a, const EmpBlockOwningSpan &b,
                   const EmpBlockOwningSpan &p,
                   EmpBlockOwningSpan &out) noexcept;

/**
   rearrange_sum_bits. This function re-arranges the bits in `sum` to match the
format expected by BoringSSL. This function does not throw.
   @param `sum`: the input and output bits. Must have a size that is divisible
by 8.
   @param `size`: the number of elements in `sum`.
**/
void rearrange_sum_bits(emp::block *const sum, const size_t size) noexcept;

/**
   rearrange_sum_bits. This function re-arranges the bits in `sum` to match the
format expected by BoringSSL. This function does not throw.
   @param `sum`: the input and output bits. Must have a size that is divisible
by 8.
**/
void rearrange_sum_bits(EmpBlockNonOwningSpan &sum) noexcept;

/**
 rearrange_sum_bits. This function re-arranges the bits in `sum` to match the
format expected by BoringSSL. This function does not throw.
 @param `sum`: the input and output bits. Must have a size that is divisible
by 8.
**/
void rearrange_sum_bits(EmpBlockOwningSpan &sum) noexcept;

// The following functions are all used for multiplication over GF(2^128).

/**
 shuffle_epi32. This function implements the _mm_shuffle_epi32 intrinsic
provided in Intel's SSE2 instruction set. The definition of this function is
given here: https://www.felixcloutier.com/x86/pshufd. Given that imm is an
immediate value, this function is free at runtime for a garbled circuit (i.e
the cost is solely at circuit generation time).
@snippet CircuitSynthesis.t.cpp CircuitSynthesisTestShuffleEpi32
@param[in] a: the blocks that are shuffled.
@param[in] imm: the immediate value used for shuffling.
@return the shuffled variant of a.
**/
EmpBlockArray<128> shuffle_epi32(const emp::block (&a)[128],
                                 const uint8_t imm) noexcept;

/**
 shuffle_epi32. This function implements the _mm_shuffle_epi32 intrinsic
provided in Intel's SSE2 instruction set. The definition of this function is
given here: https://www.felixcloutier.com/x86/pshufd. Given that imm is an
immediate value, this function is free at runtime for a garbled circuit (i.e the
cost is solely at circuit generation time).

@snippet CircuitSynthesis.t.cpp CircuitSynthesisTestShuffleEpi32
@param[in] a: the blocks that are shuffled.
@param[in] imm: the immediate value used for shuffling.
@return the shuffled variant of a.
**/
EmpBlockArray<128> shuffle_epi32(const EmpBlockArray<128> &a,
                                 const uint8_t imm) noexcept;

/**
   xor_si128. This function implements the _mm_xor_si128 instrinsic.
   Namely, this function computes the bitwise xor of `a` and `b` and
   returns the result.
   @snippet CircuitSynthesis.t.cpp CircuitSynthesisTestXorSi128
   @param[in] a: the left operand.
   @param[in] b: the right operand.
   @return the bitwise xor of `a` and `b`.
**/
EmpBlockArray<128> xor_si128(const emp::block *const a,
                             const emp::block *const b) noexcept;

/**
 xor_si128. This function implements the _mm_xor_si128 instrinsic.
 Namely, this function computes the bitwise xor of `a` and `b` and
 returns the result.
 @snippet CircuitSynthesis.t.cpp CircuitSynthesisTestXorSi128
 @param[in] a: the left operand.
 @param[in] b: the right operand.
 @return the bitwise xor of `a` and `b`.
**/
EmpBlockArray<128> xor_si128(const EmpBlockArray<128> &a,
                             const EmpBlockArray<128> &b) noexcept;

/**
   xor_si128. This function implements the _mm_xor_si128 instrinsic.
   Namely, this function computes the bitwise xor of `a` and `b` and
   returns the result.
   @snippet CircuitSynthesis.t.cpp CircuitSynthesisTestXorSi128
   @param[in] a: the left operand.
   @param[in] b: the right operand.
   @return the bitwise xor of `a` and `b`.
**/
EmpBlockArray<128> xor_si128(const emp::block (&a)[128],
                             const emp::block (&b)[128]) noexcept;

/**
   slli_si128. This function implements the _mm_slli_si128 intrinsic.
   Namely, this function shifts the array referred to by `a` to the left by
   imm * 8 bytes. Notably, this function is free for garbled circuits (it is a
generation-time cost only).
   @snippet CircuitSynthesis.t.cpp CircuitSynthesisTestSllisi128
   @param[in] a: the array that is shifted.
   @param[in] imm: the amount to shift by. This value is capped at 16.
   @return a << imm * 8.
**/
EmpBlockArray<128> slli_si128(const emp::block *const a,
                              const uint8_t imm) noexcept;
/**
   slli_si128. This function implements the _mm_slli_si128 intrinsic.
   Namely, this function shifts the array referred to by `a` to the left by
   imm * 8 bytes. Notably, this function is free for garbled circuits (it is a
generation-time cost only).
   @snippet CircuitSynthesis.t.cpp CircuitSynthesisTestSllisi128
   @param[in] a: the array that is shifted.
   @param[in] imm: the amount to shift by. This value is capped at 16.
   @return a << imm * 8.
**/
EmpBlockArray<128> slli_si128(const EmpBlockArray<128> &a,
                              const uint8_t imm) noexcept;

/**
 slli_si128. This function implements the _mm_slli_si128 intrinsic.
 Namely, this function shifts the array referred to by `a` to the left by
 imm * 8 bytes. Notably, this function is free for garbled circuits (it is a
generation-time cost only).
 @snippet CircuitSynthesis.t.cpp CircuitSynthesisTestSllisi128
 @param[in] a: the array that is shifted.
 @param[in] imm: the amount to shift by. This value is capped at 16.
 @return a << imm * 8.
**/
EmpBlockArray<128> slli_si128(const emp::block (&a)[128],
                              const uint8_t imm) noexcept;

/**
   srli_si128. This function implements the _mm_srli_si128 intrinsic.
   Namely, this function shifts the array referred to by `a` to the right by
   imm * 8 bytes. Notably, this function is free for garbled circuits (it is a
generation-time cost only).
   @snippet CircuitSynthesis.t.cpp CircuitSynthesisTestSrlisi128
   @param[in] a: the array that is shifted.
   @param[in] imm: the amount to shift by. This value is capped at 16.
   @return a >> imm * 8.
**/
EmpBlockArray<128> srli_si128(const emp::block *const a,
                              const uint8_t imm) noexcept;
/**
   srli_si128. This function implements the _mm_srli_si128 intrinsic.
   Namely, this function shifts the array referred to by `a` to the right by
   imm * 8 bytes. Notably, this function is free for garbled circuits (it is a
generation-time cost only).
   @snippet CircuitSynthesis.t.cpp CircuitSynthesisTestSrlisi128
   @param[in] a: the array that is shifted.
   @param[in] imm: the amount to shift by. This value is capped at 16.
   @return a >> imm * 8.
**/
EmpBlockArray<128> srli_si128(const EmpBlockArray<128> &a,
                              const uint8_t imm) noexcept;
/**
   srli_si128. This function implements the _mm_srli_si128 intrinsic.
   Namely, this function shifts the array referred to by `a` to the right by
   imm * 8 bytes. Notably, this function is free for garbled circuits (it is a
generation-time cost only).
   @snippet CircuitSynthesis.t.cpp CircuitSynthesisTestSrlisi128
   @param[in] a: the array that is shifted.
   @param[in] imm: the amount to shift by. This value is capped at 16.
   @return a >> imm * 8.
**/
EmpBlockArray<128> srli_si128(const emp::block (&a)[128],
                              const uint8_t imm) noexcept;

/**
   slli_epi32. This function implements the _mm_slli_epi32 intrinsic.
   Namely, this function shifts each 32-bit integer in `a` to the left by `imm`
positions. Notably, this function is free for garbled circuits (it is a
generation-time cost only).
   @snipppet CircuitSynthesis.t.cpp CircuitSynthesisTestSlliEpi32
   @param[in] a: the array that is shifted.
   @param[in] imm: the amount to shift by. This value is capped at 32.
   @return {a[0] << imm, a[1] << imm, a[2] << imm, a[3] << imm}.
**/
EmpBlockArray<128> slli_epi32(const emp::block *const a,
                              const uint8_t imm) noexcept;

/**
   slli_epi32. This function implements the _mm_slli_epi32 intrinsic.
   Namely, this function shifts each 32-bit integer in `a` to the left by `imm`
positions. Notably, this function is free for garbled circuits (it is a
generation-time cost only).
   @snipppet CircuitSynthesis.t.cpp CircuitSynthesisTestSlliEpi32
   @param[in] a: the array that is shifted.
   @param[in] imm: the amount to shift by. This value is capped at 32.
   @return {a[0] << imm, a[1] << imm, a[2] << imm, a[3] << imm}.
**/
EmpBlockArray<128> slli_epi32(const emp::block (&a)[128],
                              const uint8_t imm) noexcept;
/**
 slli_epi32. This function implements the _mm_slli_epi32 intrinsic.
 Namely, this function shifts each 32-bit integer in `a` to the left by `imm`
positions. Notably, this function is free for garbled circuits (it is a
generation-time cost only).
 @snipppet CircuitSynthesis.t.cpp CircuitSynthesisTestSlliEpi32
 @param[in] a: the array that is shifted.
 @param[in] imm: the amount to shift by. This value is capped at 32.
 @return {a[0] << imm, a[1] << imm, a[2] << imm, a[3] << imm}.
**/
EmpBlockArray<128> slli_epi32(const EmpBlockArray<128> &a,
                              const uint8_t imm) noexcept;

/**
   srli_epi32. This function implements the _mm_srli_epi32 intrinsic.
   Namely, this function shifts each 32-bit integer in `a` to the right by `imm`
positions. Notably, this function is free for garbled circuits (it is a
generation-time cost only).
   @snipppet CircuitSynthesis.t.cpp CircuitSynthesisTestSrliEpi32
   @param[in] a: the array that is shifted.
   @param[in] imm: the amount to shift by. This value is capped at 32.
   @return {a[0] >>imm, a[1] >>imm, a[2] >>imm, a[3] >>imm}.
**/
EmpBlockArray<128> srli_epi32(const emp::block *const a,
                              const uint8_t imm) noexcept;

/**
   srli_epi32. This function implements the _mm_srli_epi32 intrinsic.
   Namely, this function shifts each 32-bit integer in `a` to the right by `imm`
positions. Notably, this function is free for garbled circuits (it is a
generation-time cost only).
   @snipppet CircuitSynthesis.t.cpp CircuitSynthesisTestSrliEpi32
   @param[in] a: the array that is shifted.
   @param[in] imm: the amount to shift by. This value is capped at 32.
   @return {a[0] >>imm, a[1] >>imm, a[2] >>imm, a[3] >>imm}.
**/
EmpBlockArray<128> srli_epi32(const emp::block (&a)[128],
                              const uint8_t imm) noexcept;
/**
 srli_epi32. This function implements the _mm_srli_epi32 intrinsic.
 Namely, this function shifts each 32-bit integer in `a` to the right by `imm`
positions. Notably, this function is free for garbled circuits (it is a
generation-time cost only).
 @snipppet CircuitSynthesis.t.cpp CircuitSynthesisTestSrliEpi32
 @param[in] a: the array that is shifted.
 @param[in] imm: the amount to shift by. This value is capped at 32.
 @return {a[0] >>imm, a[1] >>imm, a[2] >>imm, a[3] >> imm}.
**/
EmpBlockArray<128> srli_epi32(const EmpBlockArray<128> &a,
                              const uint8_t imm) noexcept;

/**
   and_si128. This function implements the _mm_and_si128 instrinsic.
   Namely, this function computes the bitwise and of `a` and `b` and
   returns the result.
   @snippet CircuitSynthesis.t.cpp CircuitSynthesisTestAndSi128
   @param[in] a: the left operand.
   @param[in] b: the right operand.
   @return the bitwise and of `a` and `b`.
**/
EmpBlockArray<128> and_si128(const emp::block *const a,
                             const emp::block *const b) noexcept;

/**
 and_si128. This function implements the _mm_and_si128 instrinsic.
 Namely, this function computes the bitwise and of `a` and `b` and
 returns the result.
 @snippet CircuitSynthesis.t.cpp CircuitSynthesisTestAndSi128
 @param[in] a: the left operand.
 @param[in] b: the right operand.
 @return the bitwise and of `a` and `b`.
**/
EmpBlockArray<128> and_si128(const EmpBlockArray<128> &a,
                             const EmpBlockArray<128> &b) noexcept;

/**
   and_si128. This function implements the _mm_and_si128 instrinsic.
   Namely, this function computes the bitwise and of `a` and `b` and
   returns the result.
   @snippet CircuitSynthesis.t.cpp CircuitSynthesisTestAndSi128
   @param[in] a: the left operand.
   @param[in] b: the right operand.
   @return the bitwise and of `a` and `b`.
**/
EmpBlockArray<128> and_si128(const emp::block (&a)[128],
                             const emp::block (&b)[128]) noexcept;

/**
   andnot_si128. This function implements the _mm_andnot_si128 instrinsic.
   Namely, this function computes the bitwise and of `a` and `b` and
   returns the result.
   @snippet CircuitSynthesis.t.cpp CircuitSynthesisTestAndnotSi128
   @param[in] a: the left operand.
   @param[in] b: the right operand.
   @return the bitwise and of `a` and `b`.
**/
EmpBlockArray<128> andnot_si128(const emp::block *const a,
                                const emp::block *const b) noexcept;

/**
 andnot_si128. This function implements the _mm_andnot_si128 instrinsic.
 Namely, this function computes the bitwise and of `!a` and `b` and
 returns the result.
 @snippet CircuitSynthesis.t.cpp CircuitSynthesisTestAndnotSi128
 @param[in] a: the left operand.
 @param[in] b: the right operand.
 @return the bitwise and of `a` and `b`.
**/
EmpBlockArray<128> andnot_si128(const EmpBlockArray<128> &a,
                                const EmpBlockArray<128> &b) noexcept;

/**
   andnot_si128. This function implements the _mm_andnot_si128 instrinsic.
   Namely, this function computes the bitwise and of `a` and `b` and
   returns the result.
   @snippet CircuitSynthesis.t.cpp CircuitSynthesisTestAndnotSi128
   @param[in] a: the left operand.
   @param[in] b: the right operand.
   @return the bitwise and of `a` and `b`.
**/
EmpBlockArray<128> andnot_si128(const emp::block (&a)[128],
                                const emp::block (&b)[128]) noexcept;

} // namespace CircuitSynthesis

// Inline definitions go here
#include "CircuitSynthesis.inl"
#endif

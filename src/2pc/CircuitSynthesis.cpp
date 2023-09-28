#include "CircuitSynthesis.hpp"

#include <algorithm>
#include <bitset>
#include <cassert>

// NOTE: this function just exists to allow us to create an array of a
// fixed size and fixed value. C++20 and later have nicer ways to do this,
// but in C++17 we have to wrap everything up.
template <unsigned char value>
static constexpr std::array<unsigned char, 64> create_array() noexcept {
  std::array<unsigned char, 64> arr{};
  for (unsigned i = 0; i < 64; i++) {
    arr[i] = value;
  }

  return arr;
}

template <unsigned nr_entries>
static void reverse_bytes_internal(emp::block *const data) noexcept {
  assert(data);
  std::reverse(data, data + nr_entries);
}

void CircuitSynthesis::reverse_bytes(EmpBlockOwningSpan &blocks) noexcept {
  // This differs from the n-for-1-auth
  // code: we use std::reverse here.
  assert(blocks.data());
  std::reverse(blocks.begin(), blocks.end());
}

void CircuitSynthesis::reverse_bytes(EmpBlockNonOwningSpan blocks) noexcept {
  // This differs from the n-for-1-auth
  // code: we use std::reverse here.
  assert(blocks.data());
  std::reverse(blocks.begin(), blocks.end());
}

static void change_endian_internal(const emp::block *const input,
                                   const size_t size,
                                   emp::block *const output) noexcept {
  assert(size % 8 == 0);
  assert(input != output);
  std::copy(input, input + size, output);
  for (unsigned i = 0; i < size; i += 8) {
    reverse_bytes_internal<8>(output + i);
  }
}

void CircuitSynthesis::change_endian(const EmpBlockNonOwningSpan input,
                                     emp::block *const output) noexcept {
  change_endian_internal(input.data(), input.size(), output);
}

void CircuitSynthesis::change_endian(const EmpBlockOwningSpan &input,
                                     emp::block *const output) noexcept {
  change_endian_internal(input.data(), input.size(), output);
}

void CircuitSynthesis::change_endian_four(const emp::block *const input,
                                          emp::block *const output) noexcept {
  assert(input);
  assert(output);
  assert(input != output);

  // The algorithm here does the same as CircuitSynthesis.t.cpp's
  // n_for_1_auth_reversal. This essentially takes each block of 32-entries and
  // swaps them backwards. In particular, for i in {0, 1, 2, 3} we have that:
  // output[i*32: i*32 + 7, i*32 + 8:i*32 + 15, i*32 + 16: i*32 + 23, i*32 +
  // 24:i*32 + 31] =
  //                             input[i*32 + 24:i*32 + 31, i*32 + 16: i*32 +
  //                             23, i*32 + 8: i*32 + 15, i*32 + 0:i*32+7]
  for (unsigned i = 0; i < 8; i++) {
    auto input_iter = input + i * 32;
    auto output_iter = output + i * 32;
    std::copy(input_iter, input_iter + 8, output_iter + 24);
    std::copy(input_iter + 8, input_iter + 16, output_iter + 16);
    std::copy(input_iter + 16, input_iter + 24, output_iter + 8);
    std::copy(input_iter + 24, input_iter + 32, output_iter);
  }
}

static void padding_internal(const emp::block *const input, const size_t len,
                             emp::block *const output) noexcept {

  assert(len <= 8191);
  assert(input);
  assert(output);
  assert(input != output);

  const emp::block one = emp::CircuitExecution::circ_exec->public_label(true);
  const emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);
  // Copy over the initial input into `output`.
  std::copy(input, input + len, output);

  // Add a single bit `1`
  output[len] = one;
  // This is the amount we need to add to get a multiple of 512 as the offset.
  const auto K = CircuitSynthesis::get_K(len);
  const auto start_of_zeroes = output + len + 1;
  // This is a combination of two `zero` blocks that are added on in
  // n-for-1-auth. Essentially, n-for-1 auth pads with `K` 0 bits, and then adds
  // on an extra 48 0s too. This is because n-for-1-auth
  // places the length in the final 16-bits. This is because the input is
  // typically small. To do that without loops, we simply use std::fill. Our end
  // position is output + len + 1 + K + 48 because: 1) output+len accounts for
  // the initial copy. 2) +1 is for the single bit `1` added above. 3) `K` is
  // for the K 0s we add, and 4) the 48 is for the extra 48 0s.
  const auto end_of_zeroes = start_of_zeroes + K + 48;
  std::fill(output + len + 1, end_of_zeroes, zero);

  // Now we'll go from end_of_zeroes to end of the array and add in the length.
  auto current_pos = end_of_zeroes;
  for (unsigned i = 0; i < 16; i++) {
    const auto is_set = (len & static_cast<size_t>((1 << (16 - 1 - i)))) != 0;
    *(current_pos + i) = is_set ? one : zero;
  }
}

void CircuitSynthesis::padding(const EmpBlockOwningSpan &input,
                               emp::block *const output) noexcept {
  padding_internal(input.data(), input.size(), output);
}

template <unsigned long size, typename T>
static void arr_to_block(emp::block *const output_bits,
                         const std::array<T, size> &arr) {

  // In C++20 and later this can be a concept, but essentially we don't
  // necessarily have any guarantees that the bitwise AND operator (or the >>=
  // operator) are defined unless the type is an integral type.
  static_assert(
      std::is_integral_v<T>,
      "Error: arr_to_block can only be instantiated with an integral type");

  const auto one = emp::CircuitExecution::circ_exec->public_label(true);
  const auto zero = emp::CircuitExecution::circ_exec->public_label(false);

  // This tells us how many bits there are in each `T`.
  // This is primarily useful for extracting each entry.
  constexpr static auto bit_size_of_each = sizeof(T) * CHAR_BIT;

  for (unsigned i = 0; i < size; i++) {
    T entry = arr[i];
    for (unsigned j = 0; j < bit_size_of_each; j++) {
      output_bits[i * bit_size_of_each + j] = (entry & 1) != 0 ? one : zero;
      entry = static_cast<T>(entry >> 1);
    }
  }
}

void CircuitSynthesis::produce_digest_bits(
    emp::block *const digest_bits) noexcept {

  // Pre-condition
  assert(digest_bits);

  // SHA-256 starts with a prefixed digest. These constants are taken from
  // BoringSSL
  // (https://github.com/google/boringssl/blob/118a892d2da8c78b46ed549454b3b62ded8c84b7/crypto/fipsmodule/sha/sha256.c)
  static constexpr std::array<uint32_t, 8> digest{
      0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
      0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL};

  arr_to_block(digest_bits, digest);
}

static void
assert_valid_filepath([[maybe_unused]] const char *const filepath) noexcept {
// This function checks that filepath corresponds to a valid file.
// Otherwise, we assert(false). This will only do anything in debug builds:
// otherwise, it's an empty function.
#ifndef DNDEBUG
  FILE *f = std::fopen(filepath, "r");
  assert(f);
  std::fclose(f);
#endif
}

static void sha256_internal(const emp::block *const input,
                            const size_t input_size,
                            emp::block *const output) noexcept {

  // Pre-conditions.
  assert(input);
  assert(output);
  assert(input != output);

  // Change the endianness of the input. This is primarily for circuit
  // compatibility.

  EmpBlockOwningSpan input_new(input_size);
  change_endian_internal(input, input_size, input_new.data());

  // Now we'll pad up the newly produced input.
  const auto padded_len = CircuitSynthesis::get_padded_len(input_size);
  EmpBlockOwningSpan padded_input(padded_len);
  CircuitSynthesis::padding(input_new, padded_input.data());

  // Because padded_len is a multiple of 512 by contract (e.g get_padded_len
  // always returns a multiple of 512), this division has no rounding behaviour,
  // and so it's always precise.
  const auto num_blocks = padded_len / 512;
  emp::block input_to_sha256_circuit[768];
  emp::block output_from_sha256_circuit[256];
  emp::block digest_bits[256];
  CircuitSynthesis::produce_digest_bits(digest_bits);

  // We now load the SHA256 circuit. We use the aligned circuit from
  // n-for-1-auth.
  assert_valid_filepath(CircuitSynthesis::SHA256_FILEPATH);
  emp::BristolFormat bf(CircuitSynthesis::SHA256_FILEPATH);

  // We iterate over the input blocks in chunks of 512-bits.
  // To make this slightly easier to parse, we do this in terms of
  // iterators.
  auto iter = padded_input.cbegin();

  for (unsigned b = 0; b < num_blocks; b++) {
    // We fill up the first 512 bits with the padded input.
    std::copy(iter, iter + 512, input_to_sha256_circuit);
    // N.B We always write the 256 digest bits to input[512]. This is
    // so that the first 512 bits are the input to the hash function.
    std::copy(std::cbegin(digest_bits), std::cend(digest_bits),
              &input_to_sha256_circuit[512]);

    // This calls the SHA256 circuit.
    bf.compute(output_from_sha256_circuit, input_to_sha256_circuit,
               input_to_sha256_circuit);

    // Copy the output bits back over into the digest bits.
    std::copy(std::cbegin(output_from_sha256_circuit),
              std::cend(output_from_sha256_circuit), digest_bits);

    // Move on to the next set of blocks.
    iter += 512;
  }

  // This is just to make sure that in debug builds we've actually
  // gone over the whole array.
  assert(iter == padded_input.cend());

  // We now need to change the endianness back over.
  // This is slightly different from just reverse the whole endianness: so, we
  // use a custom routine for this.
  CircuitSynthesis::change_endian_four(output_from_sha256_circuit, output);
}

void CircuitSynthesis::sha256(const EmpBlockOwningSpan &input,
                              emp::block *const output) noexcept {
  sha256_internal(input.data(), input.size(), output);
}

void CircuitSynthesis::sha256(const EmpBlockNonOwningSpan input,
                              emp::block *const output) noexcept {
  sha256_internal(input.data(), input.size(), output);
}

static void input_key_xor(emp::block *const output, const emp::block *const key,
                          const size_t key_len) noexcept {

  // This function just applies the xor operation to output and key
  // up to key_len entries.

  assert(output);
  assert(key);

  for (unsigned i = 0; i < key_len; i++) {
    output[i] = emp::CircuitExecution::circ_exec->xor_gate(output[i], key[i]);
  }
}

static void hmac_internal(const emp::block *const key, const size_t key_len,
                          const emp::block *const data, const size_t data_len,
                          emp::block *const output) noexcept {

  // Pre-conditions.
  assert(key);
  assert(data);
  assert(output);
  assert(key != data);
  assert(key != output);
  assert(key_len <= 512);

  // These values are used for creating the ipad and opad arrays.
  // These are specified in the HMAC construction.
  static constexpr auto ipad_constant = 0x36;
  static constexpr auto opad_constant = 0x5c;

  // Create the ipad bytes. We place these bytes in the early
  // 512 blocks of our input
  EmpBlockOwningSpan input_to_hash_function(512 + data_len);
  arr_to_block(input_to_hash_function.begin(), create_array<ipad_constant>());

  // And now we apply the key to the first `key_len` entries.
  // N.B because key_len is at most 512, this will not affect
  // the remaining data bytes (see below).
  input_key_xor(input_to_hash_function.data(), key, key_len);

  // We'll copy the data into the `data_len` bytes. We start at
  // index 512 because the key is at most 512 entries long.
  std::copy(data, data + data_len, input_to_hash_function.data() + 512);

  // Warning: this portion of the code is not necessarily clear.
  // Essentially, the HMAC invocation requires chaining together calls
  // to SHA256: the output of the first invocation is fed into the second
  // invocation. To save on a stack allocation and a copy, we
  // write the output from the first sha256 call to the final 256 entries
  // of the input for the next function.
  emp::block second_input[768];
  // We'll do the first SHA256 call.
  CircuitSynthesis::sha256(input_to_hash_function, second_input + 512);

  // Note that we now fill in the first 512-entries with the key.
  arr_to_block(second_input, create_array<opad_constant>());
  input_key_xor(second_input, key, key_len);
  // N.B because second_input is stack allocated, we have to
  // use the internal sha256 function here.
  sha256_internal(second_input, 768, output);
}

void CircuitSynthesis::hmac(const EmpBlockOwningSpan &key,
                            const EmpBlockOwningSpan &data,
                            emp::block *const output) noexcept {

  hmac_internal(key.data(), key.size(), data.data(), data.size(), output);
}

void CircuitSynthesis::hmac(const EmpBlockNonOwningSpan key,
                            const EmpBlockNonOwningSpan data,
                            emp::block *const output) noexcept {
  hmac_internal(key.data(), key.size(), data.data(), data.size(), output);
}

static void hkdf_extract_internal(const emp::block *const salt,
                                  const size_t salt_size,
                                  const emp::block *const ikm,
                                  const size_t ikm_size,
                                  emp::block *const output) noexcept {

  // Pre-conditions.
  assert(ikm);
  assert(salt);
  assert(output);
  assert(output != ikm);
  assert(output != salt);

  // If there's no salt, then we have to
  // provide an all-zero key.
  if (salt_size == 0) {
    emp::block key[256];
    std::fill(std::begin(key), std::end(key),
              emp::CircuitExecution::circ_exec->public_label(false));
    hmac_internal(key, 256, ikm, ikm_size, output);
    return;
  }

  // Otherwise, we just call the hmac routine with our inputs.
  hmac_internal(salt, salt_size, ikm, ikm_size, output);
}

void CircuitSynthesis::hkdf_extract(const EmpBlockOwningSpan &salt,
                                    const EmpBlockOwningSpan &ikm,
                                    emp::block *const output) noexcept {
  hkdf_extract_internal(salt.data(), salt.size(), ikm.data(), ikm.size(),
                        output);
}

void CircuitSynthesis::hkdf_extract(const EmpBlockNonOwningSpan &salt,
                                    const EmpBlockNonOwningSpan &ikm,
                                    emp::block *const output) noexcept {
  hkdf_extract_internal(salt.data(), salt.size(), ikm.data(), ikm.size(),
                        output);
}

static void hkdf_expand_internal(const emp::block *const key,
                                 const size_t key_len,
                                 const emp::block *const info,
                                 const size_t info_len,
                                 emp::block *const output,
                                 const unsigned output_byte_len) noexcept {

  // Preconditions.
  assert(key);
  assert(info);
  assert(output);
  assert(key_len >= 256);

  // This is the number of blocks we need to process in each iteration.
  const unsigned N = (output_byte_len + 31) / 32;
  if (output_byte_len == 32) {
    assert(N == 1);
  }

  // In each iteration we'll use 256 entries.
  emp::block cur_T[256];
  EmpBlockOwningSpan input(info_len + 8);

  const emp::block one = emp::CircuitExecution::circ_exec->public_label(true);
  const emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);

  // Note: this code differs from n-for-1-auth. The first iteration of the hmac
  // is a special case for hkdf_expand, so we unroll this to keep the logic
  // cleaner.
  std::copy(info, info + info_len, input.begin());
  // Because `i == 1` in the original code, this is equivalent to setting the
  // iteration bitstring to `1`.
  input[info_len] = one;
  std::fill(input.begin() + info_len + 1, input.begin() + info_len + 8, zero);

  // Now we'll do the hmac invocation.
  hmac_internal(key, key_len, input.data(), input.size(), cur_T);

  // We'll break here if we're taking only the first output_byte_len entries.
  // The way to do this is to copy the first 256 entries at most,
  // but if not we just copy the remainder.
  const auto end = (output_byte_len >= 32)
                       ? std::cend(cur_T)
                       : std::cbegin(cur_T) + (8 * output_byte_len);
  std::copy(std::cbegin(cur_T), end, output);
  if (end != std::cend(cur_T) || N == 1) {
    return;
  }

  // And now we'll resize the input buffer to hold the right number of
  // entries. This is always 256.
  static constexpr unsigned cur_T_len = 256;
  input.init(cur_T_len + info_len + 8);
  for (unsigned i = 2; i <= N; i++) {
    // We'll move over the old output into the input.
    // The first 256 entries are the output from the previous
    // invocation, with the rest being the info data.
    std::copy(cur_T, cur_T + cur_T_len, input.data());
    std::copy(info, info + info_len, input.data() + cur_T_len);

    // Now we need to pack the iteration string.
    unsigned w = i;
    for (unsigned j = 0; j < 8; j++) {
      input[cur_T_len + info_len + j] = (w & 1) ? one : zero;
      w >>= 1;
    }

    // Now hmac.
    hmac_internal(key, key_len, input.data(), input.size(), cur_T);
    // And finally we'll conditionally copy over.
    for (unsigned j = 0; j < 256; j++) {
      const auto index = (i - 1) * 256 + j;
      // At this point there's no more work for us to do on this
      // input.
      if (index >= output_byte_len * 8) {
        return;
      }

      output[index] = cur_T[j];
    }
  }
}

void CircuitSynthesis::hkdf_expand(const EmpBlockOwningSpan &key,
                                   const EmpBlockOwningSpan &info,
                                   emp::block *const output,
                                   const unsigned output_byte_len) noexcept {
  hkdf_expand_internal(key.data(), key.size(), info.data(), info.size(), output,
                       output_byte_len);
}

void CircuitSynthesis::hkdf_expand(const EmpBlockNonOwningSpan key,
                                   const EmpBlockNonOwningSpan info,
                                   emp::block *const output,
                                   const unsigned output_byte_len) noexcept {
  hkdf_expand_internal(key.data(), key.size(), info.data(), info.size(), output,
                       output_byte_len);
}

template <typename T>
static void copy_loop(EmpBlockOwningSpan &out, unsigned start, T &value,
                      const emp::block one, const emp::block zero) noexcept {

  for (unsigned i = 0; i < 8; i++) {
    out[start++] = (value & 1) ? one : zero;
    value = static_cast<T>(value >> 1);
  }
}

static void hkdf_expand_label_internal(
    const emp::block *const key, const size_t key_len, const std::string &label,
    const emp::block *const context, const size_t context_len,
    emp::block *const output, const unsigned output_byte_len, bool) noexcept {

  // Preconditions.
  assert(key);
  assert(output);

  // The context can be empty, so long as the context length is 0.
  assert(context || context_len == 0);
  // We'll build the label first of all.
  const auto long_label = "tls13 " + label;
  // And cache the size.
  const auto long_label_len = long_label.size();

  // Now we'll have to store the hkdf_label.
  // The maths here is that we need 16 entries to store the
  // length of the output bytes, 8 for the length of the label,
  // and 8 for the length of the context.
  EmpBlockOwningSpan hkdf_label(24 + long_label_len * 8 + 8 + context_len);

  // We'll use public labels for these values.
  const auto one = emp::CircuitExecution::circ_exec->public_label(true);
  const auto zero = emp::CircuitExecution::circ_exec->public_label(false);
  // First the output_byte_length.
  unsigned in = output_byte_len;

  // We pack the bits backwards because of endianness. Most of the code here
  // is mirrored from N-for-1-Auth and checked against BoringSSL's.
  copy_loop(hkdf_label, 8, in, one, zero);
  copy_loop(hkdf_label, 0, in, one, zero);

  // We'll now pack the long_label_len.
  auto hkdf_len_in = static_cast<uint8_t>(long_label_len);
  // We've used the first 16 entries already, so we'll start from there.
  copy_loop(hkdf_label, 16, hkdf_len_in, one, zero);
  // We've just packed the next 8 entries.
  unsigned offset = 24;

  // We now pack each character of the long label into our input.
  for (unsigned i = 0; i < long_label_len; i++) {
    auto w = static_cast<unsigned char>(long_label[i]);
    copy_loop(hkdf_label, offset, w, one, zero);
    // We've processed the 8 bits in the unsigned char, so we
    // move on to the next 8.
    offset += 8;
  }

  // Pack the context len in bytes.
  auto ctext_len = static_cast<uint8_t>(context_len / 8);
  copy_loop(hkdf_label, offset, ctext_len, one, zero);
  offset += 8;

  // And finally copy over the context data. This should already be in Big
  // endian format.
  if (context_len != 0) {
    std::copy(context, context + context_len, hkdf_label.data() + offset);
  }

  assert(offset == hkdf_label.size());
  // Now we'll call the hkdf expansion.
  hkdf_expand_internal(key, key_len, hkdf_label.data(), hkdf_label.size(),
                       output, output_byte_len);
}

void CircuitSynthesis::hkdf_expand_label(const EmpBlockOwningSpan &key,
                                         const std::string &label,
                                         const EmpBlockOwningSpan &context,
                                         emp::block *const output,
                                         const unsigned output_byte_len,
                                         const bool force) noexcept {

  hkdf_expand_label_internal(key.data(), key.size(), label, context.data(),
                             context.size(), output, output_byte_len, force);
}

void CircuitSynthesis::hkdf_expand_label(const EmpBlockNonOwningSpan key,
                                         const std::string &label,
                                         const EmpBlockNonOwningSpan context,
                                         emp::block *const output,
                                         const unsigned output_byte_len,
                                         const bool force) noexcept {

  hkdf_expand_label_internal(key.data(), key.size(), label, context.data(),
                             context.size(), output, output_byte_len, force);
}

EmpBlockOwningSpan CircuitSynthesis::convert_bssl_array_to_emp_span(
    const bssl::Array<uint8_t> &a) noexcept {

  EmpBlockOwningSpan out(a.size() * CHAR_BIT);
  const auto one = emp::CircuitExecution::circ_exec->public_label(true);
  const auto zero = emp::CircuitExecution::circ_exec->public_label(false);

  // As mentioned at the class-level doc, `a` contains a big endian
  // number. Since this is only really used for the addition circuits
  // and the addition circuits expect little-endian numbers, we'll convert
  // them "backwards"
  auto offset = out.size();

  for (unsigned i = 0; i < a.size(); i++) {
    auto c = a[i];
    for (unsigned j = 0; j < CHAR_BIT; j++) {
      out[--offset] = c & 1 ? one : zero;
      c = static_cast<uint8_t>(c >> 1);
    }
  }

  // Check that the operation worked.
  assert(offset == 0);
  return out;
}

template <unsigned length>
static void add_two_mod_p_internal(const bool *const a, const bool *const b,
                                   const bool *const p,
                                   emp::block *const out) noexcept {
  // This template function adds two numbers together modulo p, treating each
  // entry as a `length` bit integer.
  // This function only works for length == 256, length == 384 and length ==
  // 521. It also only works if a, b < p (this is detailed in add_two_mod_p).

  // We'll check that first.
  static_assert(length == 256 || length == 384 || length == 521,
                "Error: can only add 256-bit, 384-bit and 521-bit numbers");

  // First of all, we have to get the right circuit that we're going to load.
  auto get_circuit_path = []() {
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
  };

  static constexpr auto file_path = get_circuit_path();
  // We'll make sure the file actually exists (in debug mode only!)
  assert_valid_filepath(file_path);

  // We'll also check in debug mode that these pointers are valid.
  assert(a);
  assert(b);
  assert(p);
  assert(out);

  // As an extra check, we'll make sure that the emp globals are valid.
  assert(emp::ProtocolExecution::prot_exec);
  assert(emp::CircuitExecution::circ_exec);

  // Now we'll load the inputs into our circuit. Note that because length is a
  // template paramter, we can stack allocate these.
  emp::block input[length * 3];

  // For some reason (i.e unknown to the author of this code) emp requires these
  // inputs to be backwards from how you'd expect them to be from the circuit
  // description. In particular, we would expect the input to be `a`, `b`, `p`,
  // whereas it is in fact `p`, `b`, `a`.
  const auto a_location = input + 2 * length;
  const auto b_location = input + length;
  const auto p_location = input;

  emp::ProtocolExecution::prot_exec->feed(a_location, emp::ALICE, a, length);
  emp::ProtocolExecution::prot_exec->feed(b_location, emp::BOB, b, length);
  emp::ProtocolExecution::prot_exec->feed(p_location, emp::PUBLIC, p, length);

  // Now we'll actually set-up the circuit. We already checked it was valid
  // above.
  emp::BristolFashion bf(file_path);
  // Carry out the protocol.
  bf.compute(out, input);
}

template <unsigned length>
static void convert_emp_to_bool(const EmpBlockOwningSpan &in,
                                const emp::block one,
                                bool *const out) noexcept {

  assert(out);
  for (unsigned i = 0; i < length; i++) {
    out[i] = emp::cmpBlock(&in[i], &one, 1);
  }
}

template <unsigned length>
static void add_two_mod_p_internal(const EmpBlockOwningSpan &a,
                                   const EmpBlockOwningSpan &b,
                                   const EmpBlockOwningSpan &p,
                                   EmpBlockOwningSpan &out) noexcept {

  // This function just converts each of `a`, `b` and `p` into the appropriate
  // boolean arrays before passing them to the other add_two_mod_p function.
  bool a_bool[length], b_bool[length], p_bool[length];

  // Check that we can actually get the label.
  assert(emp::CircuitExecution::circ_exec);
  const emp::block one = emp::CircuitExecution::circ_exec->public_label(true);

  // Convert the inputs to bools.
  convert_emp_to_bool<length>(a, one, a_bool);
  convert_emp_to_bool<length>(b, one, b_bool);
  convert_emp_to_bool<length>(p, one, p_bool);

  // And now we'll delegate to the other routine.
  add_two_mod_p_internal<length>(a_bool, b_bool, p_bool, out.data());
}

void CircuitSynthesis::add_two_mod_p(const EmpBlockOwningSpan &a,
                                     const EmpBlockOwningSpan &b,
                                     const EmpBlockOwningSpan &p,
                                     EmpBlockOwningSpan &out) noexcept {

  // All the sizes must be the same.
  assert(a.size() == b.size() && b.size() == p.size() &&
         p.size() == out.size());
  const auto length = a.size();
  // Sizes must match up.
  assert(length == 256 || length == 384 || length == 521);
  // We'll just use the internal routine with the right length.

  switch (length) {
  case 256:
    add_two_mod_p_internal<256>(a, b, p, out);
    return;
  case 384:
    add_two_mod_p_internal<384>(a, b, p, out);
    return;
  case 521:
    add_two_mod_p_internal<521>(a, b, p, out);
    return;
  }
}

void CircuitSynthesis::add_two_mod_p(const bool *const a, const bool *const b,
                                     const bool *const p, emp::block *const out,
                                     const unsigned length) noexcept {

  // We'll check the pointers are valid here. This is repeated in
  // add_two_mod_p_internal, but the error messages are nicer here and in
  // optimised builds these aren't enabled anyway
  assert(a);
  assert(b);
  assert(p);
  assert(out);

  // We only support these circuit sizes.
  // These circuit sizes correspond to the characteristic of the base field
  // used by the NIST curves.
  assert(length == 256 || length == 384 || length == 521);

  // Just delegate to the child routine for each case.
  switch (length) {
  case 256:
    add_two_mod_p_internal<256>(a, b, p, out);
    return;
  case 384:
    add_two_mod_p_internal<384>(a, b, p, out);
    return;
  case 521:
    add_two_mod_p_internal<521>(a, b, p, out);
    return;
  }
}

static void rearrange_sum_bits_internal(emp::block *const begin,
                                        emp::block *const end,
                                        const size_t size) noexcept {
  assert(begin);
  assert(end);
  assert(size % 8 == 0);

  const auto width = size / 8;
  for (unsigned i = 0; i < width; i++) {
    std::reverse(begin + i * 8, begin + (i + 1) * 8);
  }
  std::reverse(begin, end);
}

void CircuitSynthesis::rearrange_sum_bits(emp::block *const sum,
                                          const size_t size) noexcept {
  rearrange_sum_bits_internal(sum, sum + size, size);
}

void CircuitSynthesis::rearrange_sum_bits(EmpBlockOwningSpan &sum) noexcept {
  rearrange_sum_bits_internal(sum.begin(), sum.end(), sum.size());
}

void CircuitSynthesis::rearrange_sum_bits(EmpBlockNonOwningSpan &sum) noexcept {
  rearrange_sum_bits_internal(sum.begin(), sum.end(), sum.size());
}

EmpBlockArray<128> CircuitSynthesis::shuffle_epi32(const emp::block (&a)[128],
                                                   const uint8_t imm) noexcept {
  EmpBlockArray<128> out{};

  const auto first = 32 * (imm & 3);
  const auto second = 32 * ((imm >> 2) & 3);
  const auto third = 32 * ((imm >> 4) & 3);
  const auto fourth = 32 * ((imm >> 6) & 3);

  std::copy(std::cbegin(a) + first, std::cbegin(a) + first + 32,
            std::begin(out));
  std::copy(std::cbegin(a) + second, std::cbegin(a) + second + 32,
            std::begin(out) + 32);
  std::copy(std::cbegin(a) + third, std::cbegin(a) + third + 32,
            std::begin(out) + 64);
  std::copy(std::cbegin(a) + fourth, std::cbegin(a) + fourth + 32,
            std::begin(out) + 96);
  return out;
}

EmpBlockArray<128> CircuitSynthesis::shuffle_epi32(const EmpBlockArray<128> &a,
                                                   const uint8_t imm) noexcept {
  return CircuitSynthesis::shuffle_epi32(a.get_arr(), imm);
}

EmpBlockArray<128>
CircuitSynthesis::xor_si128(const emp::block *const a,
                            const emp::block *const b) noexcept {
  EmpBlockArray<128> out;
  for (unsigned i = 0; i < 128; i++) {
    out[i] = emp::CircuitExecution::circ_exec->xor_gate(a[i], b[i]);
  }
  return out;
}

EmpBlockArray<128>
CircuitSynthesis::xor_si128(const EmpBlockArray<128> &a,
                            const EmpBlockArray<128> &b) noexcept {
  return CircuitSynthesis::xor_si128(a.data(), b.data());
}

EmpBlockArray<128>
CircuitSynthesis::xor_si128(const emp::block (&a)[128],
                            const emp::block (&b)[128]) noexcept {
  return CircuitSynthesis::xor_si128(&a[0], &b[0]);
}

template <bool left>
static EmpBlockArray<128> shift_si128(const emp::block *const a,
                                      const uint8_t imm) noexcept {
  assert(a);
  const auto shift_by = 8 * ((imm > 15) ? 16 : imm);
  const auto nr_to_copy = 128 - shift_by;
  const emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);

  EmpBlockArray<128> out;

  if (left) {
    std::copy(a, a + nr_to_copy, out.begin() + shift_by);
    std::fill(out.begin(), out.begin() + shift_by, zero);
  } else {
    std::copy(a + shift_by, a + 128, out.begin());
    std::fill(out.begin() + nr_to_copy, out.end(), zero);
  }

  return out;
}

EmpBlockArray<128> CircuitSynthesis::slli_si128(const emp::block *const a,
                                                const uint8_t imm) noexcept {
  return shift_si128<true>(a, imm);
}

EmpBlockArray<128> CircuitSynthesis::slli_si128(const EmpBlockArray<128> &a,
                                                const uint8_t imm) noexcept {
  return shift_si128<true>(a.data(), imm);
}

EmpBlockArray<128> CircuitSynthesis::slli_si128(const emp::block (&a)[128],
                                                const uint8_t imm) noexcept {
  return shift_si128<true>(&a[0], imm);
}

EmpBlockArray<128> CircuitSynthesis::srli_si128(const emp::block *const a,
                                                const uint8_t imm) noexcept {
  return shift_si128<false>(a, imm);
}

EmpBlockArray<128> CircuitSynthesis::srli_si128(const EmpBlockArray<128> &a,
                                                const uint8_t imm) noexcept {
  return shift_si128<false>(a.data(), imm);
}

EmpBlockArray<128> CircuitSynthesis::srli_si128(const emp::block (&a)[128],
                                                const uint8_t imm) noexcept {
  return shift_si128<false>(&a[0], imm);
}

template <bool left>
static EmpBlockArray<32> shift_single_epi32(const emp::block *const a,
                                            const uint8_t imm) noexcept {
  assert(a);
  EmpBlockArray<32> out;
  const emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);
  std::fill(out.begin(), out.end(), zero);
  const auto shift_by = imm;
  const auto nr_to_copy = 32 - shift_by;
  if (left) {
    std::copy(a, a + nr_to_copy, out.begin() + shift_by);
  } else {
    std::copy(a + shift_by, a + 32, out.begin());
  }

  return out;
}

template <bool left>
static EmpBlockArray<128> shift_epi32(const emp::block *const a,
                                      const uint8_t imm) noexcept {
  assert(a);
  // Cap to a 32 element shift (at most).
  const auto shift_by = uint8_t((imm > 31) ? 32 : imm);

  EmpBlockArray<128> out;
  const auto first = shift_single_epi32<left>(a, shift_by);
  const auto second = shift_single_epi32<left>(a + 32, shift_by);
  const auto third = shift_single_epi32<left>(a + 64, shift_by);
  const auto fourth = shift_single_epi32<left>(a + 96, shift_by);
  std::copy(first.cbegin(), first.cend(), out.begin());
  std::copy(second.cbegin(), second.cend(), out.begin() + 32);
  std::copy(third.cbegin(), third.cend(), out.begin() + 64);
  std::copy(fourth.cbegin(), fourth.cend(), out.begin() + 96);
  return out;
}

EmpBlockArray<128> CircuitSynthesis::slli_epi32(const emp::block *const a,
                                                const uint8_t imm) noexcept {
  return shift_epi32<true>(a, imm);
}

EmpBlockArray<128> CircuitSynthesis::slli_epi32(const emp::block (&a)[128],
                                                const uint8_t imm) noexcept {

  return shift_epi32<true>(&a[0], imm);
}

EmpBlockArray<128> CircuitSynthesis::slli_epi32(const EmpBlockArray<128> &a,
                                                const uint8_t imm) noexcept {
  return shift_epi32<true>(a.data(), imm);
}

EmpBlockArray<128> CircuitSynthesis::srli_epi32(const emp::block *const a,
                                                const uint8_t imm) noexcept {
  return shift_epi32<false>(a, imm);
}

EmpBlockArray<128> CircuitSynthesis::srli_epi32(const emp::block (&a)[128],
                                                const uint8_t imm) noexcept {
  return shift_epi32<false>(&a[0], imm);
}

EmpBlockArray<128> CircuitSynthesis::srli_epi32(const EmpBlockArray<128> &a,
                                                const uint8_t imm) noexcept {
  return shift_epi32<false>(a.data(), imm);
}

EmpBlockArray<128>
CircuitSynthesis::and_si128(const emp::block *const a,
                            const emp::block *const b) noexcept {
  assert(a);
  assert(b);
  EmpBlockArray<128> out;
  for (unsigned i = 0; i < 128; i++) {
    out[i] = emp::CircuitExecution::circ_exec->and_gate(a[i], b[i]);
  }
  return out;
}

EmpBlockArray<128>
CircuitSynthesis::and_si128(const EmpBlockArray<128> &a,
                            const EmpBlockArray<128> &b) noexcept {
  return CircuitSynthesis::and_si128(a.data(), b.data());
}

EmpBlockArray<128>
CircuitSynthesis::and_si128(const emp::block (&a)[128],
                            const emp::block (&b)[128]) noexcept {
  return CircuitSynthesis::and_si128(&a[0], &b[0]);
}

EmpBlockArray<128>
CircuitSynthesis::andnot_si128(const emp::block *const a,
                               const emp::block *const b) noexcept {
  assert(a);
  assert(b);
  EmpBlockArray<128> out;
  for (unsigned i = 0; i < 128; i++) {
    out[i] = emp::CircuitExecution::circ_exec->and_gate(
        emp::CircuitExecution::circ_exec->not_gate(a[i]), b[i]);
  }
  return out;
}

EmpBlockArray<128>
CircuitSynthesis::andnot_si128(const EmpBlockArray<128> &a,
                               const EmpBlockArray<128> &b) noexcept {
  return CircuitSynthesis::andnot_si128(a.data(), b.data());
}

EmpBlockArray<128>
CircuitSynthesis::andnot_si128(const emp::block (&a)[128],
                               const emp::block (&b)[128]) noexcept {
  return CircuitSynthesis::andnot_si128(&a[0], &b[0]);
}

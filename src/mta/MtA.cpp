#include "MtA.hpp"
#include "../ssl/EmpWrapper.hpp"
#include "../ssl/Util.hpp"
#include <algorithm>
#include <emp-ot/emp-ot.h>

static bool serialise_bignums_init(const size_t in_size,
                                   const unsigned size_of_each,
                                   PackArray &out) noexcept {
  // Pre-conditions on the size.
  if (in_size == 0 || size_of_each == 0) {
    return false;
  }
  // This is just to make sure that each bignum is neatly convertible
  // to a sequence of blocks: each function in this namespace needs this.
  assert(size_of_each % sizeof(emp::block) == 0);
  return out.init(in_size * size_of_each);
}

bool MtA::generate_random_vector_inplace(bssl::Array<BIGNUM *> &out,
                                         const BIGNUM &q) noexcept {

  // NOTE: BN_rand_range_ex is enough here.
  // According to the API doc, the only thing that is leaked is the range:
  // this is already known to both parties, and the values themselves
  // are apparently also protected. 
  const auto size = out.size();
  for (unsigned i = 0; i < size; i++) {
    if (!BN_rand_range_ex(out[i], 1, &q)) {
      return false;
    }
  }
  return true;
}

static bool generate_random_vector_init(bssl::Array<BIGNUM *> &out,
                                        const uint64_t vector_size,
                                        BN_CTX &ctx) {
  if (!out.Init(vector_size)) {
    return false;
  }

  for (unsigned i = 0; i < out.size(); i++) {
    out[i] = BN_CTX_get(&ctx);
    if (!out[i]) {
      return false;
    }
  }
  return true;
}

bool MtA::generate_random_vector(bssl::Array<BIGNUM *> &out,
                                 const uint64_t vector_size, const BIGNUM &q,
                                 BN_CTX &ctx) noexcept {
  return generate_random_vector_init(out, vector_size, ctx) &&
         generate_random_vector_inplace(out, q);
}

bool MtA::receiver_ot(emp::IKNP<EmpWrapper<>>& ot, EmpBlockOwningSpan &r,
                      const bssl::Array<bool> &choices) noexcept {
  // We bail if the size of `r` or `choices` don't
  // match, or even if there's no blocks to read into.
  // This is primarily expected to be something that's hit in test cases
  // rather than in production.
  if (r.size() != choices.size() || r.size() == 0) {
    return false;
  }

  ot.recv(r.data(), choices.data(), static_cast<int64_t>(choices.size()));
  return true;
}

bool MtA::receiver_ot(emp::FerretCOT<EmpWrapper<>>& ot, EmpBlockOwningSpan &r,
                      const bssl::Array<bool> &choices) noexcept {
  // We bail if the size of `r` or `choices` don't
  // match, or even if there's no blocks to read into.
  // This is primarily expected to be something that's hit in test cases
  // rather than in production.
  if (r.size() != choices.size() || r.size() == 0) {
    return false;
  }

  ot.recv(r.data(), choices.data(), static_cast<int64_t>(choices.size()));
  return true;
}

bool MtA::receiver_ot(SSL * const ssl, EmpBlockOwningSpan &r,
                      const bssl::Array<bool> &choices) noexcept {
  // We bail if the size of `r` or `choices` don't
  // match, or even if there's no blocks to read into.
  // This is primarily expected to be something that's hit in test cases
  // rather than in production.
  if (!ssl || r.size() != choices.size() || r.size() == 0) {
    return false;
  }

  // Create a new wrapper.
  EmpWrapper<> wrapper { ssl };
  emp::IKNP<EmpWrapper<>> ot(&wrapper, true);
  ot.recv(r.data(), choices.data(), static_cast<int64_t>(choices.size()));
  return true;
}


bool MtA::convert_arr_to_block_inplace(const PackArray &arr,
                                       EmpBlockOwningSpan &blocks) noexcept {

  // Pre-conditions: no point breaking up a zero-sized array.
  // Similarly, if the blocks are empty, then we return.
  if (arr.size() == 0 || blocks.size() == 0) {
    return false;
  }

  assert(arr.size() % sizeof(emp::block) == 0);
  assert(blocks.size() == arr.size() / sizeof(emp::block));
  // And now just memcpy over the top. This is legal because char* can alias
  // any other type (and because sizeof(uint8_t) == sizeof(char) by definition).
  memcpy(reinterpret_cast<char *>(blocks.data()), arr.data(), arr.size());
  return true;
}

static void convert_arr_to_block_init(EmpBlockOwningSpan &b,
                                      const size_t arr_size) noexcept {
  // Here we rely upon the fact that `arr.size()` is a multiple of emp::block.
  // This is primarily to make the code correct without needing to explicitly
  // deal with rounding.
  assert(arr_size % sizeof(emp::block) == 0);
  b.init(arr_size / sizeof(emp::block));
  return;
}

EmpBlockOwningSpan MtA::convert_arr_to_block(const PackArray &arr) noexcept {
  // Note: the failure cases are hidden inside convert_arr_to_block_init and
  // convert_arr_to_block_inplace.
  EmpBlockOwningSpan b;

  // Allocate the blocks.
  convert_arr_to_block_init(b, arr.size());
  // And now just delegate to the convert_arr_to_block_inplace routine.
  // Note that we ignore the return type, because the caller deals with
  // everything.
  convert_arr_to_block_inplace(arr, b);
  // FWIW if `b` has size 0 then this will be an empty span: as per the error
  // condition.
  return b;
}

static bool convert_block_to_arr_init(PackArray &arr,
                                      const size_t number_of_entries) noexcept {
  // If there's no entries in the sets of blocks, then there's been an error.
  return number_of_entries != 0 &&
         arr.init(sizeof(emp::block) * number_of_entries);
}

bool MtA::convert_block_to_arr_inplace(const EmpBlockOwningSpan &blocks,
                                       PackArray &arr) noexcept {

  // If there's no entries in the set of blocks, then there's been an error.
  if (blocks.size() == 0) {
    return false;
  }

  // This is to make sure that the copies line up.
  assert(arr.size() == sizeof(emp::block) * blocks.size());
  // And now just memcpy over the top. Again, this is legal because char * can
  // alias any other type.
  memcpy(arr.data(), reinterpret_cast<const char *>(blocks.data()), arr.size());
  return true;
}

bool MtA::convert_block_to_arr(const EmpBlockOwningSpan &blocks,
                               PackArray &arr) noexcept {
  // Note: the error conditions here are hidden inside both
  // convert_block_to_arr_init and covert_block_to_arr_inplace, but they're
  // sufficiently combinable.
  return convert_block_to_arr_init(arr, blocks.size()) &&
         convert_block_to_arr_inplace(blocks, arr);
}

bool MtA::expand_t_to_ot_width_inplace(const size_t ots_per_bignum,
                                       const bssl::Array<bool> &t,
                                       bssl::Array<bool> &out) noexcept {

  // Pre-conditions
  assert(ots_per_bignum != 0);
  assert(out.size() == ots_per_bignum * t.size());

  // Here we just do the copying over.
  // This code should be read as follows: we fill in curr -> curr +
  // ots_per_bignum - 1 with t[i]. This should compile down to a broadcast /
  // scatter in asm, which is cheap. N.B because `t` and `out` may alias, we
  // explicitly extract out the length here (it shouldn't matter but you never
  // know because aliasing rules are hard).
  const auto size = t.size();
  auto *curr = out.data();
  assert(curr);

  for (unsigned i = 0; i < size; i++) {
    std::fill(curr, curr + ots_per_bignum, t[i]);
    curr += ots_per_bignum;
  }

  assert(curr == out.end());
  return true;
}

static bool expand_t_to_ot_width_init(const size_t ots_per_bignum,
                                      const size_t nr_entries,
                                      bssl::Array<bool> &out) noexcept {
  return out.Init(ots_per_bignum * nr_entries);
}

bool MtA::expand_t_to_ot_width(const unsigned max_bytes,
                               const bssl::Array<bool> &t,
                               bssl::Array<bool> &out) noexcept {
  // Each EMP block is ~128 bits / 16 bytes (this should be a stable assumption,
  // but it may depend on the platform).
  // This doesn't really work for us in this situation: we instead
  // have to group multiple OTs into a single OT conceptually.
  // To do this, we expand the choice bits so that we can select
  // the entire bignum, depending on the width of each bignum.

  // Conceptually, this function works as follows:
  // 1) We know that each bignum we want to encode takes at most `max_bytes`
  // bytes. This means that we have max_bytes / sizeof(emp::block) many
  // oblivious transfers per bignum. 2) We expand `t` into an array (`out`) that
  // contains exactly t.size() * (max_bytes / sizeof(emp::block)) booleans. This
  // means we have a bool per sizeof(emp::block) "chunk" of each bignum. 3)
  // Finally, we expand out each t[i] into `out`: each t[i] gets duplicated
  // (max_bytes / sizeof(emp::block) times, as this corresponds to extracting
  // the whole message.

  // Of course, we don't allow a zero-sized array or a zero-sized prime.
  if (t.size() == 0 || max_bytes == 0) {
    return false;
  }

  // These assertions are just to make sure the logic holds above (i.e that the
  // above code covers these special cases, which unless we hit UB should
  // definitely hold).
  assert(max_bytes % sizeof(emp::block) == 0);
  const auto ots_per_bignum = max_bytes / sizeof(emp::block);

  // With that, delegate to the expansion and building routines.
  return expand_t_to_ot_width_init(ots_per_bignum, t.size(), out) &&
         expand_t_to_ot_width_inplace(ots_per_bignum, t, out);
}

bool MtA::generate_t_and_v_inplace(const BIGNUM &b, const BIGNUM &q,
                                   bssl::Array<bool> &t,
                                   bssl::Array<BIGNUM *> &v,
                                   BN_CTX &ctx) noexcept {
  // This is the number of entries in both `v` and `t`.
  const auto n = BN_num_bits(&q) + MtA::k;
  assert(t.size() == n);
  assert(v.size() == n);

  // Pack `v` with random entries mod q.
  if (!generate_random_vector_inplace(v, q)) {
    return false;
  }

  // NOTE: this could be done better -- we can do a much smarter
  // generation here by generating wider entries to minimise
  // the number of calls to rand().
  // However, there's not really any guarantees on `n` that would
  // easily allow us to split this up.
  for (unsigned i = 0; i < n; i++) {
    t[i] = rand();
  }

  // These hold the <v, t> and b - <v, t> respectively.
  BIGNUM *total = BN_CTX_get(&ctx);
  BIGNUM *diff = BN_CTX_get(&ctx);
  if (!total || !diff) {
    return false;
  }

  // And now compute the inner product. We implicitly map each `t[i]` to its
  // value {-1, 1}. To do this, we take {0, 1} and treat each 0 as a call to a
  // subtraction routine: otherwise, we take it as a call to a multiplication
  // routine.
  for (unsigned i = 0; i < n - 1; i++) {
    // Remarkably, a ternary is actually the neatest way to write this.
    const auto failed = (t[i]) ? !BN_mod_add(total, total, v[i], &q, &ctx)
                               : !BN_mod_sub(total, total, v[i], &q, &ctx);
    if (failed) {
      return false;
    }
  }

  // Now we need to adjust the entries so they line up properly.
  // This works by computing the difference between `b` and `total`, and then
  // adding that difference to a random entry in `v`.
  // To make this less predictable, we'll randomly move this around.
  // We use the cryptographically secure random number generator in Util
  // to make the result less predictable.
  // It isn't clear that this actually needs to be cryptographically random, but for
  // the sake of a single unsigned int it's probably worth it to be safe, although this
  // function is definitely not constant time.
  unsigned pos;
  if (!Util::generate_random_bytes<sizeof(pos)>(&pos)) {
    return false;
  }

  // Bring pos back in range.
  pos = pos % (n-1);
  
  t[n - 1] = true;
  std::swap(t[n - 1], t[pos]);

  // The sub here is so we "re-add" the difference later on (because t[pos] is
  // true).
  if (!BN_mod_sub(v[n - 1], &b, total, &q, &ctx)) {
    return false;
  }

  // Finally swap over the changed bignums.
  std::swap(v[n - 1], v[pos]);
  return true;
}

static bool generate_t_and_v_init(const BIGNUM &q, bssl::Array<bool> &t,
                                  bssl::Array<BIGNUM *> &v,
                                  BN_CTX &ctx) noexcept {

  // This is the number of entries in both `v` and `t`.
  const auto n = BN_num_bits(&q) + MtA::k;
  // We'll allocate both `t` and `v` to be the right size, and then delegate
  // to the inplace routine.
  if (!v.Init(n) || !t.Init(n)) {
    return false;
  }

  for (unsigned i = 0; i < n; i++) {
    v[i] = BN_CTX_get(&ctx);
    if (!v[i]) {
      return false;
    }
  }
  return true;
}

bool MtA::generate_t_and_v(const BIGNUM &b, const BIGNUM &q,
                           bssl::Array<bool> &t, bssl::Array<BIGNUM *> &v,
                           BN_CTX &ctx) noexcept {
  // The error conditions and logic are actually contained in
  // the initialisation and generation routines.
  return generate_t_and_v_init(q, t, v, ctx) &&
         MtA::generate_t_and_v_inplace(b, q, t, v, ctx);
}

bool MtA::produce_sender_pairs_inplace(const bssl::Array<BIGNUM *> &delta,
                                       const BIGNUM *const a,
                                       const unsigned size_of_each,
                                       PackArray &add_pack, PackArray &sub_pack,
                                       const BIGNUM *const q,
                                       BN_CTX *const ctx) noexcept {
  // Nullness and size checks.
  const auto n = delta.size();
  if (!a || !q || !ctx || n == 0) {
    return false;
  }

  // Pre-condition: we expect the size of each bignum to be
  // divisible by the size of each block, due to padding constraints.
  assert(size_of_each % sizeof(emp::block) == 0);
  assert(add_pack.size() == size_of_each * n);
  assert(sub_pack.size() == size_of_each * n);

  // These each contain a temporary for delta[i] + a, delta[i] - a respectively.
  // This is primarily to save on allocations.
  BIGNUM *const add = BN_CTX_get(ctx);
  BIGNUM *const sub = BN_CTX_get(ctx);
  if (!add || !sub) {
    return false;
  }

  // We'll write to each pack using pointer arithmetic. At each step of the
  // loop, we'll move along by `size_of_each` bytes.
  auto *add_data = add_pack.data();
  auto *sub_data = sub_pack.data();

  for (unsigned i = 0; i < n; i++) {
    if (!BN_mod_add(add, delta[i], a, q, ctx) ||
        !BN_mod_sub(sub, delta[i], a, q, ctx)) {
      return false;
    }

    if (!BN_bn2bin_padded(add_data, size_of_each, add) ||
        !BN_bn2bin_padded(sub_data, size_of_each, sub)) {
      return false;
    }
    add_data += size_of_each;
    sub_data += size_of_each;
  }

  // Just make sure that the arithmetic holds up.
  assert(add_data == add_pack.end());
  assert(sub_data == sub_pack.end());
  return true;
}

static bool initialise_entries_for_receiver_internal(
    const BIGNUM *const q, BN_CTX *const ctx, bssl::Array<bool> &t,
    bssl::Array<bool> &t_extended, bssl::Array<BIGNUM *> &v,
    PackArray &v_serialised, bssl::Array<uint8_t> &sigma_serialised,
    EmpBlockOwningSpan &z) noexcept {

  if (!q || !ctx) {
    return false;
  }

  const auto n = BN_num_bits(q) + MtA::k;
  const auto size_of_each = MtA::round_up_to_block(BN_num_bytes(q));
  assert(size_of_each >= BN_num_bytes(q));

  if (!generate_t_and_v_init(*q, t, v, *ctx)) {
    return false;
  }

  const auto ots_per_bignum = size_of_each / sizeof(emp::block);
  if (!expand_t_to_ot_width_init(ots_per_bignum, n, t_extended)) {
    return false;
  }

  if (!serialise_bignums_init(n, size_of_each, v_serialised)) {
    return false;
  }

  if (!sigma_serialised.Init(size_of_each)) {
    return false;
  }

  z.init(t_extended.size());
  return true;
}

bool MtA::initialise_entries_for_receiver(const BIGNUM *const q,
                                          ReceiverEntry &entry,
                                          BN_CTX *const ctx) noexcept {
  return initialise_entries_for_receiver_internal(
      q, ctx, entry.t, entry.t_extended, entry.v, entry.v_serialised,
      entry.sigma_serialised, entry.z);
}

template<typename OTType>
static bool play_receiver_inplace_internal(
    BIGNUM *const out, OTType& ot, const BIGNUM *const b,
    const BIGNUM *const q, BN_CTX *const ctx, bssl::Array<bool> &t,
    bssl::Array<bool> &t_extended, bssl::Array<BIGNUM *> &v,
    PackArray &v_serialised, bssl::Array<uint8_t> &sigma_serialised,
    EmpBlockOwningSpan &z) noexcept {
  // Pre-condition checks.
  if (!out || !b || !q || !ctx) {
    return false;
  }

  // We now generate `t` and `v`, as per
  // step 2 of Protocol 4.10.
  // We also need to (potentially) pad out how many bits we need to represent
  // each bignum.
  const auto size_of_each = MtA::round_up_to_block(BN_num_bytes(q));
  // It should round up.
  assert(size_of_each >= BN_num_bytes(q));

  // We need to work out how many blocks we need (this is for the expansion
  // below).
  const auto ots_per_bignum = size_of_each / sizeof(emp::block);

  // See the documentation for expand_t_to_ot_width for why this expansion
  // is necessary (it's to do with packing).
  if (!MtA::generate_t_and_v_inplace(*b, *q, t, v, *ctx) ||
      !MtA::expand_t_to_ot_width_inplace(ots_per_bignum, t, t_extended) ||
      !MtA::serialise_bignums_inplace(v_serialised, v, size_of_each)) {
    return false;
  }

  // These checks are just to make sure that all the sizes line up as expected.
  assert(t_extended.size() == size_of_each / sizeof(emp::block) * t.size());
  assert(v.size() == BN_num_bits(q) + MtA::k);
  assert(v_serialised.size() == v.size() * size_of_each);

  // For correctness, we also generate `sigma` (again, as per step 2).
  // This is an extra mask to use during the protocol (this helps with
  // simulability).
  BIGNUM *sigma = BN_CTX_get(ctx);
  if (!sigma || !BN_rand_range_ex(sigma, 1, q) ||
      !BN_bn2bin_padded(sigma_serialised.data(), size_of_each, sigma)) {
    return false;
  }

  // We'll do t_extended OTs in total. This corresponds to asking for t.size()
  // bignums, but we need to pad out to make sure we get the whole bignums at
  // each step (again, see the namespace documentation for more).
  if (!MtA::receiver_ot(ot, z, t_extended)) {
    return false;
  }

  // BoringSSL signifies a write failure by returning a value that's
  // different from the `len` parameter: hence, we check that we actually
  // write the whole message.
  const auto v_serial_bytes = static_cast<int>(v_serialised.size());
  const auto s_serial_bytes = static_cast<int>(sigma_serialised.size());

  auto* ssl = ot.io->get_ssl();
  
  if (SSL_write(ssl, v_serialised.data(), v_serial_bytes) != v_serial_bytes ||
      SSL_write(ssl, sigma_serialised.data(), s_serial_bytes) !=
          s_serial_bytes) {
    return false;
  }

  // Now we do the inner product. Here we're implicitly treating `z` as a
  // sequence of bignums: the deserialise_inner_product function deals with the
  // conversions for us.
  // N.B this zeroing may not be needed, but it's better to be safe.
  BN_zero(out);

  // We need this to hold the result of the inner product, since
  // BN_mod_add's API doesn't explicitly allow overlapping arguments.
  BIGNUM *tmp = BN_CTX_get(ctx);
  if (!tmp) {
    return false;
  }

  return MtA::deserialise_inner_product(tmp, z, v, size_of_each, q, ctx) &&
         BN_mod_add(out, tmp, sigma, q, ctx);
}

bool MtA::play_receiver_inplace_iknp(BIGNUM *const out,
                                     emp::IKNP<EmpWrapper<>> &ot,
                                     const BIGNUM *const b,
                                     const BIGNUM *const q, BN_CTX *const ctx,
                                     ReceiverEntry &entry) noexcept {
  return play_receiver_inplace(out, ot, b, q, ctx, entry);
}

bool MtA::play_receiver_inplace(BIGNUM *const out, emp::IKNP<EmpWrapper<>>& ot,
                                const BIGNUM *const b, const BIGNUM *const q,
                                BN_CTX *const ctx,
                                ReceiverEntry &entry) noexcept {
  // We'll now just expand out each parameter (a la Python's parameter
  // unpacking) and call the internal sender.
  return play_receiver_inplace_internal(
      out, ot, b, q, ctx, entry.t, entry.t_extended, entry.v,
      entry.v_serialised, entry.sigma_serialised, entry.z);
}

bool MtA::play_receiver_inplace(BIGNUM *const out, emp::FerretCOT<EmpWrapper<>>& ot,
                                const BIGNUM *const b, const BIGNUM *const q,
                                BN_CTX *const ctx,
                                ReceiverEntry &entry) noexcept {
  // We'll now just expand out each parameter (a la Python's parameter
  // unpacking) and call the internal sender.
  return play_receiver_inplace_internal(
      out, ot, b, q, ctx, entry.t, entry.t_extended, entry.v,
      entry.v_serialised, entry.sigma_serialised, entry.z);
}

bool MtA::play_receiver(BIGNUM *const out, emp::FerretCOT<EmpWrapper<>>& ot,
                        const BIGNUM *const b, const BIGNUM *const q,
                        BN_CTX *const ctx) noexcept {

  // Pre-condition checks.
  if (!out || !b || !q || !ctx) {
    return false;
  }

  // We just delegate out to the initialisation and playing routines.
  ReceiverEntry re;
  return MtA::initialise_entries_for_receiver(q, re, ctx) &&
         MtA::play_receiver_inplace(out, ot, b, q, ctx, re);
}

bool MtA::play_receiver(BIGNUM *const out, emp::IKNP<EmpWrapper<>>& ot,
                        const BIGNUM *const b, const BIGNUM *const q,
                        BN_CTX *const ctx) noexcept {

  // Pre-condition checks.
  if (!out || !b || !q || !ctx) {
    return false;
  }

  // We just delegate out to the initialisation and playing routines.
  ReceiverEntry re;
  return MtA::initialise_entries_for_receiver(q, re, ctx) &&
         MtA::play_receiver_inplace(out, ot, b, q, ctx, re);
}

static bool produce_sender_pairs_init(PackArray &add_pack, PackArray &sub_pack,
                                      const size_t n,
                                      const size_t size_of_each) noexcept {
  // Pre-condition: we expect the size of each bignum to be divisible
  // by the size of each block, due to padding constraints.
  assert(size_of_each % sizeof(emp::block) == 0);
  return add_pack.init(size_of_each * n) && sub_pack.init(size_of_each * n);
}

bool MtA::produce_sender_pairs(const bssl::Array<BIGNUM *> &delta,
                               const BIGNUM *const a,
                               const unsigned size_of_each, PackArray &add_pack,
                               PackArray &sub_pack, const BIGNUM *const q,
                               BN_CTX *const ctx) noexcept {

  // Nullness and size checks.
  const auto n = delta.size();
  if (!a || !q || !ctx || n == 0) {
    return false;
  }

  // All of the error conditions are dealt with in the individual functions.
  return produce_sender_pairs_init(add_pack, sub_pack, n, size_of_each) &&
         produce_sender_pairs_inplace(delta, a, size_of_each, add_pack,
                                      sub_pack, q, ctx);
}

bool MtA::serialise_bignums_inplace(PackArray &out,
                                    const bssl::Array<BIGNUM *> &in,
                                    const unsigned size_of_each) noexcept {

  // We'll write to `out` using pointer arithmetic. For each iteration
  // of the loop below, we'll move forward by size_of_each bytes.
  uint8_t *curr = out.data();
  assert(size_of_each * in.size() == out.size());

  for (unsigned i = 0; i < in.size(); i++) {
    if (!BN_bn2bin_padded(curr, size_of_each, in[i])) {
      return false;
    }

    curr += size_of_each;
  }

  // Just to make sure the arithmetic works out.
  assert(curr == out.end());
  return true;
}

bool MtA::serialise_bignums(PackArray &out, const bssl::Array<BIGNUM *> &in,
                            const unsigned size_of_each) noexcept {
  // The error conditions are handled, again, by the called functions.
  return serialise_bignums_init(in.size(), size_of_each, out) &&
         serialise_bignums_inplace(out, in, size_of_each);
}

static bool deserialise_inner_product_internal(
    BIGNUM *const out, const bssl::Span<const uint8_t> lhs,
    const bssl::Span<const BIGNUM *const> rhs, const unsigned size_of_each,
    const BIGNUM *const q, BN_CTX *const ctx) noexcept {
  // Various correctness pre-conditions.
  if (!out || !q || !ctx || size_of_each == 0 || rhs.size() == 0 ||
      lhs.size() == 0 || lhs.size() != size_of_each * rhs.size()) {
    return false;
  }

  // To make life easier, we'll do the reconstruction one element at a time.
  // This also saves on allocations.
  BIGNUM *deserialised = BN_CTX_get(ctx);
  BIGNUM *tmp = BN_CTX_get(ctx);
  BIGNUM *s1 = BN_CTX_get(ctx);
  if (!deserialised || !tmp || !s1) {
    return false;
  }

  // We'll use pointer arithmetic to walk through the loop. Each increment is
  // in `size_of_each` batches.
  const uint8_t *curr = lhs.data();

  // This just zeros out `out`. This may be redundant, depending on the caller,
  // but it's good to make sure.
  BN_zero(out);
  for (unsigned i = 0; i < rhs.size(); i++) {
    if (!BN_bin2bn(curr, size_of_each, deserialised) ||
        !BN_mod_mul(tmp, rhs[i], deserialised, q, ctx) ||
        !BN_mod_add(s1, out, tmp, q, ctx) || !BN_copy(out, s1)) {
      return false;
    }
    curr += size_of_each;
  }

  // We should be at the end of the `lhs` array: otherwise either `size_of_each`
  // or the pointer arithmetic was wrong.
  assert(curr == lhs.cend());
  return true;
}

bool MtA::deserialise_inner_product(BIGNUM *const out, const PackArray &lhs,
                                    const bssl::Array<BIGNUM *> &rhs,
                                    const unsigned size_of_each,
                                    const BIGNUM *const q, BN_CTX *const ctx) {
  return deserialise_inner_product_internal(
      out, bssl::Span<const uint8_t>(lhs.data(), lhs.size()),
      bssl::Span<const BIGNUM *const>(rhs.data(), rhs.size()), size_of_each, q,
      ctx);
}

bool MtA::deserialise_inner_product(BIGNUM *const out,
                                    const EmpBlockOwningSpan &lhs,
                                    const bssl::Array<BIGNUM *> &rhs,
                                    const unsigned size_of_each,
                                    const BIGNUM *const q,
                                    BN_CTX *const ctx) noexcept {

  // Note: this is legal C++ because uint8_t can alias any type.
  // The inverse is _not_ true: we cannot use emp::block to alias any
  // uint8_t, because the alignment isn't guaranteed (and anyway, that
  // would be UB in C++).
  return deserialise_inner_product_internal(
      out,
      bssl::Span<const uint8_t>(reinterpret_cast<const uint8_t *>(lhs.data()),
                                lhs.size_in_bytes()),
      bssl::Span<const BIGNUM *const>(rhs.data(), rhs.size()), size_of_each, q,
      ctx);
}


template<typename OTType>
static bool sender_ot_internal(OTType &ot,
                               const emp::block *const b0,
                               const emp::block *const b1,
                               const int64_t size) noexcept {
  // No pre-conditions: the caller is responsible for checking them.
  ot.send(b0, b1, static_cast<int64_t>(size));
  return true;
}

bool MtA::sender_ot(emp::IKNP<EmpWrapper<>> &ot, const EmpBlockOwningSpan &b0,
                    const EmpBlockOwningSpan &b1) noexcept {
  // Pre-conditions.
  if (b1.size() != b0.size() || b1.size() == 0) {
    return false;
  }

  // Just delegate to the actual implementation.
  return sender_ot_internal(ot, b0.data(), b1.data(),
                            static_cast<int64_t>(b0.size()));
}

bool MtA::sender_ot(emp::FerretCOT<EmpWrapper<>> &ot, const EmpBlockOwningSpan &b0,
                    const EmpBlockOwningSpan &b1) noexcept {
  // Pre-conditions.
  if (b1.size() != b0.size() || b1.size() == 0) {
    return false;
  }

  // Just delegate to the actual implementation.
  return sender_ot_internal(ot, b0.data(), b1.data(),
                            static_cast<int64_t>(b0.size()));
}

bool MtA::sender_ot(SSL * const ssl, const EmpBlockOwningSpan &b0,
                    const EmpBlockOwningSpan &b1) noexcept {
  // Pre-conditions.
  if (!ssl || b1.size() != b0.size() || b1.size() == 0) {
    return false;
  }

  // Create a new wrapper.
  EmpWrapper<> wrapper { ssl };
  emp::IKNP<EmpWrapper<>> ot(&wrapper, true);
  
  // Just delegate to the actual implementation.
  return sender_ot_internal(ot, b0.data(), b1.data(),
                            static_cast<int64_t>(b0.size()));
}


static bool initialise_entries_for_sender_internal(
    const unsigned n, const BIGNUM *const q, bssl::Array<BIGNUM *> &delta,
    PackArray &add_pack, PackArray &sub_pack, PackArray &vals,
    bssl::Array<uint8_t> &sigma_v, BN_CTX *const ctx) noexcept {
  // This function allocates memory for all of the parameters.
  if (!q || !ctx) {
    return false;
  }

  if (!generate_random_vector_init(delta, n, *ctx)) {
    return false;
  }

  const auto size_of_each = MtA::round_up_to_block(BN_num_bytes(q));
  if (!produce_sender_pairs_init(add_pack, sub_pack, n, size_of_each)) {
    return false;
  }

  return vals.init(n * size_of_each) && sigma_v.Init(size_of_each);
}

bool MtA::initialise_entries_for_sender(const unsigned n, const BIGNUM *const q,
                                        SenderEntry &se,
                                        BN_CTX *const ctx) noexcept {
  return initialise_entries_for_sender_internal(
      n, q, se.delta, se.add_pack, se.sub_pack, se.vals, se.sigma_v, ctx);
}

bool MtA::initialise_entries_for_sender(const BIGNUM *const q, SenderEntry &se,
                                        BN_CTX *const ctx) noexcept {
  if (!q || !ctx) {
    return false;
  }
  const auto n = BN_num_bits(q) + MtA::k;
  return initialise_entries_for_sender(n, q, se, ctx);
}

template<typename OTType>
static bool play_sender_inplace_internal(
    BIGNUM *const out, OTType &ot, const BIGNUM *const a,
    const BIGNUM *const q, BN_CTX *const ctx, const unsigned n,
    bssl::Array<BIGNUM *> &delta, PackArray &add_pack, PackArray &sub_pack,
    PackArray &vals, bssl::Array<uint8_t> &sigma_v) noexcept {

  // Generate the random vector `delta` for the inner products.
  if (!MtA::generate_random_vector_inplace(delta, *q)) {
    return false;
  }

  // With that, we'll generate the packs we'll need.
  // There's `n` bignums for each entry, each taking up size_of_each
  // bytes. We round up the size to make the OTs easier to pack.
  const auto size_of_each = MtA::round_up_to_block(BN_num_bytes(q));
  // Make sure that the rounding actually worked.
  assert(size_of_each >= BN_num_bytes(q));

  // This corresponds to Step 1 b) of the protocol: we produce each OT pair.
  if (!MtA::produce_sender_pairs_inplace(delta, a, size_of_each, add_pack,
                                         sub_pack, q, ctx)) {
    return false;
  }

  // We now need to dump those pairs into blocks, because emp expects
  // the messages as blocks. We already allocated these earlier:
  // Now we'll do oblivious transfer.
  if (!add_pack.data() || !sub_pack.data()) {
    return false;
  }

  // Now we'll convert the packs into blocks. This is a technically dangerous
  // operation, but it should work because the packs themselves have the same
  // alignment as emp::block.
  const auto *const b0 = reinterpret_cast<const emp::block *>(sub_pack.data());
  const auto *const b1 = reinterpret_cast<const emp::block *>(add_pack.data());

  // Now we need to compute the size in blocks.
  assert(sub_pack.size() % sizeof(emp::block) == 0);
  assert(add_pack.size() % sizeof(emp::block) == 0);

  const auto size_in_blocks = sub_pack.size() / sizeof(emp::block);

  if (!sender_ot_internal(ot, b0, b1, static_cast<int64_t>(size_in_blocks))) {
    return false;
  }

  // With that done, we need to read the `v` array from the sender. That array
  // contains `n` bignums, each taking up size_of_each bytes. We also
  // have to read sigma, which takes up size_of_each bytes.
  // This corresponds to Step "2.5" of the protocol.
  BIGNUM *sigma = BN_CTX_get(ctx);
  if (!sigma) {
    return false;
  }

  const auto vals_size = static_cast<int>(n * size_of_each);
  const auto sigma_size = static_cast<int>(size_of_each);

  // Note: reading `vals` here needs to happen in a loop. Essentially, there's a
  // limit on the amount of data that OpenSSL can send in any given plaintext,
  // which in some situations may be lower than what we want to receive here.
  // Hence we iterate until we've read the whole amount of data.
  auto * const ssl = ot.io->get_ssl();
  
  int read_data = 0;
  while (read_data < vals_size) {
    const auto recv =
        SSL_read(ssl, vals.data() + read_data, vals_size - read_data);
    // This implies an error.
    if (recv <= 0) {
      return false;
    }
    read_data += recv;
  }

  // By contrast, sigma itself should be really small, and so
  // we don't need to loop.
  assert(sigma_size < SSL3_RT_MAX_PLAIN_LENGTH);
  if (SSL_read(ssl, sigma_v.data(), sigma_size) != sigma_size ||
      !BN_bin2bn(sigma_v.data(), sigma_v.size(), sigma)) {
    return false;
  }

  // Now we'll do Step 3 of the protocol.
  // This comprises computing -<vals, delta> and then subtracting off sigma.
  BIGNUM *share = BN_CTX_get(ctx);
  BIGNUM *tmp = BN_CTX_get(ctx);
  BIGNUM *zero = BN_CTX_get(ctx);

  if (!share || !tmp || !zero ||
      !MtA::deserialise_inner_product(tmp, vals, delta, size_of_each, q, ctx) ||
      !BN_mod_sub(share, zero, tmp, q, ctx)) {
    return false;
  }

  return BN_mod_sub(out, share, sigma, q, ctx);
}

bool MtA::play_sender_inplace_iknp(BIGNUM *const out,
                                   emp::IKNP<EmpWrapper<>> &ot,
                                   const BIGNUM *const a, const BIGNUM *const q,
                                   BN_CTX *const ctx,
                                   SenderEntry &se) noexcept {
  return play_sender_inplace(out, ot, a, q, ctx, se);
}

bool MtA::play_sender_inplace(BIGNUM *const out, emp::IKNP<EmpWrapper<>> &ot,
                              const BIGNUM *const a, const BIGNUM *const q,
                              BN_CTX *const ctx, SenderEntry &se) noexcept {

  // // `n` here is the number of OTs to carry out (conceptually),
  // as per the "common input" of the protocol.
  const unsigned n = BN_num_bits(q) + MtA::k;
  // We should make sure that `a` is actually representable
  // as an element mod `q`.
  assert(BN_num_bits(q) >= BN_num_bits(a));

  // Just delegate to the internal routine.
  return play_sender_inplace_internal(out, ot, a, q, ctx, n, se.delta,
                                      se.add_pack, se.sub_pack, se.vals,
                                      se.sigma_v);
}

bool MtA::play_sender_inplace(BIGNUM *const out, emp::FerretCOT<EmpWrapper<>> &ot,
                              const BIGNUM *const a, const BIGNUM *const q,
                              BN_CTX *const ctx, SenderEntry &se) noexcept {

  // // `n` here is the number of OTs to carry out (conceptually),
  // as per the "common input" of the protocol.
  const unsigned n = BN_num_bits(q) + MtA::k;
  // We should make sure that `a` is actually representable
  // as an element mod `q`.
  assert(BN_num_bits(q) >= BN_num_bits(a));

  // Just delegate to the internal routine.
  return play_sender_inplace_internal(out, ot, a, q, ctx, n, se.delta,
                                      se.add_pack, se.sub_pack, se.vals,
                                      se.sigma_v);
}

bool MtA::play_sender(BIGNUM *const out, emp::IKNP<EmpWrapper<>> &ot, const BIGNUM *const a,
                      const BIGNUM *const q, BN_CTX *const ctx) noexcept {
  // `n` here is the number of OTs to carry out (conceptually),
  // as per the "common input" of the protocol.
  const unsigned n = BN_num_bits(q) + MtA::k;
  // We should make sure that `a` is actually representable
  // as an element mod `q`.
  assert(BN_num_bits(q) >= BN_num_bits(a));

  // Here we'll just generate the temporaries we'll need, and then delegate
  // to the actual implementation.
  SenderEntry se{};
  return MtA::initialise_entries_for_sender(n, q, se, ctx) &&
         MtA::play_sender_inplace(out, ot, a, q, ctx, se);
}

bool MtA::play_sender(BIGNUM *const out, emp::FerretCOT<EmpWrapper<>> &ot, const BIGNUM *const a,
                      const BIGNUM *const q, BN_CTX *const ctx) noexcept {
  // `n` here is the number of OTs to carry out (conceptually),
  // as per the "common input" of the protocol.
  const unsigned n = BN_num_bits(q) + MtA::k;
  // We should make sure that `a` is actually representable
  // as an element mod `q`.
  assert(BN_num_bits(q) >= BN_num_bits(a));

  // Here we'll just generate the temporaries we'll need, and then delegate
  // to the actual implementation.
  SenderEntry se{};
  return MtA::initialise_entries_for_sender(n, q, se, ctx) &&
         MtA::play_sender_inplace(out, ot, a, q, ctx, se);
}

#include "MtA.hpp"
#include "../doctest.h"
#include "../ssl/EmpWrapper.hpp"
#include "../ssl/TLSSocket.hpp"
#include "../ssl/TestUtil.hpp"
#include <mutex>

// This is just a helper function for generating random primes
static int generate_n_bit_prime(BIGNUM *prim, int bits, int safe) {
  return BN_generate_prime_ex(prim, bits, safe, nullptr, nullptr, nullptr);
}

//! [MtARoundUp]
TEST_CASE("round_up") {
  for (unsigned i = 0; i < 1000; i++) {
    const auto ro = MtA::round_up_to_block(i);
    REQUIRE(ro % sizeof(emp::block) == 0);
    REQUIRE(ro >= i);
  }
}
//! [MtARoundUp]

//! [MtAGenerateRandomVectorTests]
TEST_CASE("generate_random_vector") {
  // This is just to make sure that we can actually generate a random vector of
  // a given size.
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  bssl::Array<BIGNUM *> out;
  // We'll use a fixed-size array.
  static constexpr auto vector_size = 512;
  static constexpr int prime_sizes[]{8, 16, 32, 64, 128, 256, 512};
  for (auto prime_size : prime_sizes) {
    // Generate a random prime to use as a modulus.
    BIGNUM *q = BN_CTX_get(bn_ctx.get());
    REQUIRE(q);
    // Last parameter means we'll use a safe prime. No real reason for this.
    REQUIRE(generate_n_bit_prime(q, prime_size, 1));

    REQUIRE(MtA::generate_random_vector(out, vector_size, *q, *bn_ctx.get()));
    CHECK(out.size() == vector_size);
    for (auto element : out) {
      CHECK(BN_cmp(element, q) < 0);
    }
  }
}
//! [MtAGenerateRandomVectorTests]

//! [MtAGenerateRandomVectorInplaceTests]
TEST_CASE("generate_random_vector_inplace") {
  // This is just to make sure that we can actually generate a random vector of
  // a given size.
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  bssl::Array<BIGNUM *> out;
  // We'll use a fixed-size array.
  static constexpr auto vector_size = 512;
  static constexpr int prime_sizes[]{8, 16, 32, 64, 128, 256, 512};
  for (auto prime_size : prime_sizes) {
    // Generate a random prime to use as a modulus.
    BIGNUM *q = BN_CTX_get(bn_ctx.get());
    REQUIRE(q);
    // Last parameter means we'll use a safe prime. No real reason for this.
    REQUIRE(generate_n_bit_prime(q, prime_size, 1));
    // We'll allocate `out` here.
    REQUIRE(out.Init(vector_size));
    for (unsigned i = 0; i < vector_size; i++) {
      out[i] = BN_CTX_get(bn_ctx.get());
      REQUIRE(out[i]);
    }

    REQUIRE(MtA::generate_random_vector_inplace(out, *q));
    // We expect the generation not to screw with the length at all.
    REQUIRE(out.size() == vector_size);
    for (auto element : out) {
      CHECK(BN_cmp(element, q) < 0);
    }
  }
}
//! [MtAGenerateRandomVectorInplaceTests]

//! [MtAGenerateTandVTests]
TEST_CASE("generate_t_and_v") {
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  bssl::Array<BIGNUM *> out;
  // We'll use a fixed-size array.
  static constexpr int prime_sizes[]{8, 16, 32, 64, 128, 256, 512};
  for (auto prime_size : prime_sizes) {
    // Generate a random prime to use as a modulus.
    BIGNUM *q = BN_CTX_get(bn_ctx.get());
    REQUIRE(q);
    // Last parameter means we'll use a safe prime. No real reason for this.
    REQUIRE(generate_n_bit_prime(q, prime_size, 1));

    // Now we'll create a new element that is less than `q` to act as `b`.
    BIGNUM *b = BN_CTX_get(bn_ctx.get());
    REQUIRE(b);
    REQUIRE(BN_rand_range_ex(b, 1, q));

    bssl::Array<bool> t;
    bssl::Array<BIGNUM *> v;

    SUBCASE("Generates properly") {
      // Now we'll check that we can actually generate these entries.
      REQUIRE(MtA::generate_t_and_v(*b, *q, t, v, *bn_ctx.get()));
      const auto n = BN_num_bits(q) + MtA::k;
      REQUIRE(t.size() == n);
      REQUIRE(v.size() == n);

      // With that, we expect to have a vector `t`, `v` such that
      // we can view t * v as an approximate subset sum for `b` (approximate
      // here is because `t` is actually {0,1}^n, and not {-1, 1}^n.
      // To check that, we map `t` to {-1, 1}^n.
      BIGNUM *total = BN_CTX_get(bn_ctx.get());
      REQUIRE(total);

      for (unsigned i = 0; i < n; i++) {
        if (t[i]) {
          CHECK(BN_mod_add(total, total, v[i], q, bn_ctx.get()));
        } else {
          CHECK(BN_mod_sub(total, total, v[i], q, bn_ctx.get()));
        }
      }

      // We expect that v * t == b.
      CHECK(BN_cmp(total, b) == 0);
    }
  }
}
//! [MtAGenerateTandVTests]

//! [MtAExpandTToOtWidthTests]
TEST_CASE("expand_t_to_ot_width") {
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());
  bssl::Array<BIGNUM *> out;

  SUBCASE("Fails if max_bytes is 0") {
    // It doesn't make any sense to allow a prime that takes 0 bytes.
    bssl::Array<bool> t, t_exp;
    // Make sure this isn't the failure point.
    REQUIRE(t.Init(100));
    CHECK(!MtA::expand_t_to_ot_width(0, t, t_exp));
  }

  SUBCASE("Fails if passed a zero-sized array") {
    // This is just to make sure that a zero-sized entry fails.
    // This is primarily for robustness
    bssl::Array<bool> t, t_exp;
    REQUIRE(t.size() == 0);
    CHECK(!MtA::expand_t_to_ot_width(4, t, t_exp));
  }

  // The handling for large and small primes is slightly different. To make
  // life easier, we verify these separately.
  BIGNUM *q = BN_CTX_get(bn_ctx.get());
  REQUIRE(q);
  BIGNUM *b = BN_CTX_get(bn_ctx.get());
  bssl::Array<bool> t, t_expanded;
  bssl::Array<BIGNUM *> v;

  SUBCASE("Works for small primes") {
    static constexpr int prime_sizes[]{2, 4, 8, 16, 32, 64};
    for (auto prime_size : prime_sizes) {
      // The last parameter here means we don't require a safe prime. This is
      // _not_ arbitrary: it's a bit unlikely for small bit sizes that we'll
      // have many safe primes.
      REQUIRE(generate_n_bit_prime(q, prime_size, 0));
      const unsigned n = static_cast<unsigned>(prime_size) + MtA::k;
      // Now we'll create a new element that is less than `q` to act as `b`.
      REQUIRE(BN_rand_range_ex(b, 1, q));

      // Now we'll generate the sender pairs.
      REQUIRE(MtA::generate_t_and_v(*b, *q, t, v, *bn_ctx.get()));
      REQUIRE(t.size() == n);
      REQUIRE(v.size() == n);
      // Expansion here leads to an array that is the same size as the one that
      // went in.
      REQUIRE(MtA::expand_t_to_ot_width(MtA::round_up_to_block(BN_num_bytes(q)),
                                        t, t_expanded));
      const auto are_same_size = (t.size() == t_expanded.size());
      CHECK(are_same_size);
      if (are_same_size) {
        CHECK(memcmp(t.data(), t_expanded.data(), t.size() * sizeof(bool)) ==
              0);
      }
    }
  }

  SUBCASE("Works for large primes") {
    // Here we just use larger primes to trigger different code paths.
    static constexpr int prime_sizes[]{128, 256, 512};
    for (auto prime_size : prime_sizes) {
      // This check is primarily to make sure that the loop is set-up properly.
      REQUIRE(prime_size >= CHAR_BIT * sizeof(emp::block));
      // Last parameter means we'll use a safe prime. No real reason for this.
      REQUIRE(generate_n_bit_prime(q, prime_size, 1));
      // And this check is also to test the test code :)
      REQUIRE(BN_num_bytes(q) >= sizeof(emp::block));
      // Now we'll create a new element that is less than `q` to act as `b`.
      REQUIRE(BN_rand_range_ex(b, 1, q));

      const unsigned n = static_cast<unsigned>(prime_size) + MtA::k;
      REQUIRE(MtA::generate_t_and_v(*b, *q, t, v, *bn_ctx.get()));
      REQUIRE(t.size() == n);
      REQUIRE(v.size() == n);
      // Now we'll expand `t`.
      const auto max_bytes = BN_num_bytes(q);
      // This is the number of blocks per bignum.
      const auto entries_per_block = max_bytes / sizeof(emp::block);
      REQUIRE(MtA::expand_t_to_ot_width(max_bytes, t, t_expanded));
      // Check that t_expanded is the right width.
      REQUIRE(t_expanded.size() == t.size() * entries_per_block);
      // And now check that for each run of values we have the same value
      // duplicated in t_expanded.
      bool *elem = &t_expanded[0];
      for (unsigned i = 0; i < t.size(); i++) {
        for (unsigned j = 0; j < entries_per_block; j++) {
          CHECK(*elem == t[i]);
          elem++;
        }
      }
      // Now check that passing a fixed-size array into
      // expand_t_to_ot_width_inplace
      // does the same thing.
      // Here entries_per_block is the right size for each OT.
      bssl::Array<bool> out_inplace;
      REQUIRE(out_inplace.Init(t_expanded.size()));
      REQUIRE(
          MtA::expand_t_to_ot_width_inplace(entries_per_block, t, out_inplace));
      CHECK(memcmp(out_inplace.data(), t_expanded.data(), t_expanded.size()) ==
            0);
    }
  }
}
//! [MtAExpandTToOtWidthTests]

//! [MtAConversionTests]
TEST_CASE("conversion_tests") {
  SUBCASE("Fails if size == 0") {
    PackArray arr;
    // The null-ness of this doesn't matter because the
    // function will return _before_ it is hit.
    EmpBlockOwningSpan out{};
    CHECK(MtA::convert_arr_to_block(arr).size() == 0);
    CHECK(!MtA::convert_block_to_arr(out, arr));
  }

  SUBCASE("Works with normal values") {
    static constexpr unsigned vector_sizes[] = {
        2 * sizeof(emp::block), 4 * sizeof(emp::block), 8 * sizeof(emp::block),
        16 * sizeof(emp::block)};
    for (auto size : vector_sizes) {
      PackArray in;
      REQUIRE(in.init(size));
      for (unsigned i = 0; i < in.size(); i++) {
        in[i] = static_cast<uint8_t>(rand());
      }

      // Now pack it.
      auto as_blocks = MtA::convert_arr_to_block(in);
      REQUIRE(as_blocks.data());

      // If we do a memory comparison across the blocks the result
      // should be the same.
      CHECK(memcmp(as_blocks.data(), in.data(), in.size()) == 0);
      // Now converting back should also work.
      PackArray out;
      REQUIRE(MtA::convert_block_to_arr(as_blocks, out));
      CHECK(memcmp(out.data(), in.data(), in.size()) == 0);
    }
  }
}
//! [MtAConversionTests]

//! [MtAConversionInplaceTests]
TEST_CASE("conversion_inplace_tests") {
  SUBCASE("Fails if size == 0") {
    PackArray arr;
    // The null-ness of this doesn't matter because the
    // function will return _before_ it is hit.
    EmpBlockOwningSpan out{};
    CHECK(!MtA::convert_arr_to_block_inplace(arr, out));
    CHECK(!MtA::convert_block_to_arr_inplace(out, arr));
  }

  SUBCASE("Works with normal values") {
    static constexpr unsigned vector_sizes[] = {
        2 * sizeof(emp::block), 4 * sizeof(emp::block), 8 * sizeof(emp::block),
        16 * sizeof(emp::block)};
    for (auto size : vector_sizes) {
      PackArray in;
      REQUIRE(in.init(size));
      for (unsigned i = 0; i < in.size(); i++) {
        in[i] = static_cast<uint8_t>(rand());
      }

      // Now pack it.
      EmpBlockOwningSpan as_blocks(in.size() / sizeof(emp::block));
      REQUIRE(MtA::convert_arr_to_block_inplace(in, as_blocks));

      // If we do a memory comparison across the blocks the result
      // should be the same.
      CHECK(memcmp(as_blocks.data(), in.data(), in.size()) == 0);
      // Now converting back should also work.
      PackArray out;
      REQUIRE(out.init(sizeof(emp::block) * as_blocks.size()));
      REQUIRE(MtA::convert_block_to_arr_inplace(as_blocks, out));
      CHECK(memcmp(out.data(), in.data(), in.size()) == 0);
    }
  }
}
//! [MtAConversionInplaceTests]

//! [MtASerialiseDeserialisedPreReqs]
TEST_CASE("serialise_prereqs") {
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());
  PackArray ints;
  bssl::Array<BIGNUM *> bns;

  SUBCASE("Cannot pass in zero-sized in array") {
    REQUIRE(ints.size() == 0);
    REQUIRE(bns.size() == 0);
    CHECK(!MtA::serialise_bignums(ints, bns, 1));
  }

  REQUIRE(ints.init(5));
  REQUIRE(bns.Init(5));

  SUBCASE("Cannot pass in zero-sized entries") {
    CHECK(!MtA::serialise_bignums(ints, bns, 0));
  }
}
//! [MtASerialiseDeserialisedPreReqs]

//! [MtASerialiseBignumTests]
TEST_CASE("serialise_bignums") {
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());
  static constexpr int prime_sizes[]{8, 16, 32, 64, 128, 256, 512};
  for (auto prime_size : prime_sizes) {
    // Generate a random prime to use as a modulus.
    BIGNUM *q = BN_CTX_get(bn_ctx.get());
    REQUIRE(q);
    // Last parameter means we'll use a safe prime. No real reason for this.
    REQUIRE(generate_n_bit_prime(q, prime_size, 1));
    // Now we'll generate a list of random elements.
    bssl::Array<BIGNUM *> delta;
    const auto size_of_each = MtA::round_up_to_block(BN_num_bytes(q));
    const auto n = MtA::k + BN_num_bits(q);
    REQUIRE(MtA::generate_random_vector(delta, n, *q, *bn_ctx.get()));

    // Serialise them
    PackArray serialised;
    REQUIRE(MtA::serialise_bignums(serialised, delta, size_of_each));

    // Now we'll deserialise each entry and compare to make sure it worked.
    BIGNUM *curr = BN_CTX_get(bn_ctx.get());
    REQUIRE(curr);
    uint8_t *elem = serialised.data();

    for (unsigned i = 0; i < delta.size(); i++) {
      REQUIRE(BN_bin2bn(elem, size_of_each, curr));
      CHECK(BN_cmp(curr, delta[i]) == 0);
      elem += size_of_each;
    }
  }
}
//! [MtASerialiseBignumTests]

//! [MtADeserialiseInnerProduct]
TEST_CASE("deserialise_inner_product") {
  // This function checks that we can compute the "deserialised inner product"
  // of a list of bignums, `delta`, and a deserialised set of values `v`,
  // modulo some prime.
  PackArray serialised;
  bssl::Array<BIGNUM *> delta;
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  BIGNUM *q;
  BIGNUM *out;
  SUBCASE("Fails if out is null") {
    out = nullptr;
    q = nullptr;
    CHECK(!MtA::deserialise_inner_product(out, serialised, delta, 1, q,
                                          bn_ctx.get()));
  }

  out = BN_CTX_get(bn_ctx.get());
  REQUIRE(out);

  SUBCASE("Fails if q is null") {
    q = nullptr;
    CHECK(!MtA::deserialise_inner_product(out, serialised, delta, 1, q,
                                          bn_ctx.get()));
  }

  SUBCASE("Fails if ctx is null") {
    q = BN_CTX_get(bn_ctx.get());
    REQUIRE(q);
    CHECK(
        !MtA::deserialise_inner_product(out, serialised, delta, 1, q, nullptr));
  }

  SUBCASE("Fails if size of each entry is 0") {
    CHECK(!MtA::deserialise_inner_product(out, serialised, delta, 0, q,
                                          bn_ctx.get()));
  }

  SUBCASE("Fails if size of either serialised or delta is 0") {
    SUBCASE("Both are empty") {
      REQUIRE(delta.empty());
      REQUIRE(serialised.empty());
      CHECK(!MtA::deserialise_inner_product(out, serialised, delta, 1, q,
                                            bn_ctx.get()));
    }

    SUBCASE("serialised is empty") {
      REQUIRE(delta.Init(5));
      REQUIRE(serialised.empty());
      CHECK(!MtA::deserialise_inner_product(out, serialised, delta, 1, q,
                                            bn_ctx.get()));
    }

    SUBCASE("delta is empty") {
      REQUIRE(serialised.init(5));
      REQUIRE(delta.empty());
      CHECK(!MtA::deserialise_inner_product(out, serialised, delta, 1, q,
                                            bn_ctx.get()));
    }
  }

  SUBCASE("Fails if size doesn't match up") {
    SUBCASE("Fails if serialised does not have the right number of bytes") {
      REQUIRE(serialised.init(20));
      REQUIRE(delta.Init(6));
      CHECK(!MtA::deserialise_inner_product(out, serialised, delta, 3, q,
                                            bn_ctx.get()));
    }

    SUBCASE("Fails if delta does not have the right number of elements") {
      REQUIRE(serialised.init(18));
      REQUIRE(delta.Init(5));
      CHECK(!MtA::deserialise_inner_product(out, serialised, delta, 3, q,
                                            bn_ctx.get()));
    }
  }

  SUBCASE("Works otherwise") {
    static constexpr int prime_sizes[]{8, 16, 32, 64, 128, 256, 512};
    for (auto prime_size : prime_sizes) {
      // Generate a random prime to use as a modulus.
      q = BN_CTX_get(bn_ctx.get());
      REQUIRE(q);
      // Last parameter means we'll use a safe prime. No real reason for this.
      REQUIRE(generate_n_bit_prime(q, prime_size, 1));
      // We'll generate a random `a` and a random vector of `deltas`.
      bssl::Array<BIGNUM *> a_bignums;
      const auto n = MtA::k + BN_num_bits(q);
      const auto size_of_each = MtA::round_up_to_block(BN_num_bytes(q));
      REQUIRE(MtA::generate_random_vector(delta, n, *q, *bn_ctx.get()));
      REQUIRE(MtA::generate_random_vector(a_bignums, n, *q, *bn_ctx.get()));
      // Now we'll serialise the entries in `a_bignums`.

      REQUIRE(MtA::serialise_bignums(serialised, a_bignums, size_of_each));
      // And finally we'll get the inner product from
      // deserialise_inner_product.
      REQUIRE(MtA::deserialise_inner_product(out, serialised, delta,
                                             size_of_each, q, bn_ctx.get()));
      // We now have the inner product in `out`. But we can also recover it
      // from the values we passed in to make sure it worked.
      BIGNUM *val = BN_CTX_get(bn_ctx.get());
      BIGNUM *total = BN_CTX_get(bn_ctx.get());
      REQUIRE(val);
      REQUIRE(total);
      for (unsigned i = 0; i < n; i++) {
        REQUIRE(BN_mod_mul(val, delta[i], a_bignums[i], q, bn_ctx.get()));
        REQUIRE(BN_mod_add(total, total, val, q, bn_ctx.get()));
      }

      CHECK(BN_cmp(total, out) == 0);
    }
  }
}
//! [MtADeserialiseInnerProduct]

//! [MtADeserialiseInnerProductBlocks]
TEST_CASE("deserialise_inner_product_blocks") {
  // This test case makes sure that we can do the inner product, but with
  // the conversion to blocks too.
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());
  static constexpr int prime_sizes[]{8, 16, 32, 64, 128, 256, 512};
  for (auto prime_size : prime_sizes) {
    // Generate a random prime to use as a modulus.
    BIGNUM *q = BN_CTX_get(bn_ctx.get());
    REQUIRE(q);
    // Last parameter means we'll use a safe prime. No real reason for this.
    REQUIRE(generate_n_bit_prime(q, prime_size, 1));
    // We'll generate a random `a` and a random vector of `deltas`.
    bssl::Array<BIGNUM *> a_bignums, delta;
    const auto n = MtA::k + BN_num_bits(q);
    const auto size_of_each = MtA::round_up_to_block(BN_num_bytes(q));
    REQUIRE(MtA::generate_random_vector(delta, n, *q, *bn_ctx.get()));
    REQUIRE(MtA::generate_random_vector(a_bignums, n, *q, *bn_ctx.get()));

    // Now we'll serialise one of them.
    PackArray serialised_a;
    REQUIRE(MtA::serialise_bignums(serialised_a, a_bignums, size_of_each));
    // Now we'll dump those into a set of blocks.
    const auto b0 = MtA::convert_arr_to_block(serialised_a);
    REQUIRE(b0.data());
    REQUIRE(b0.size_in_bytes() == a_bignums.size() * size_of_each);

    // OK, now let's compute <b0, delta>.
    BIGNUM *deser = BN_CTX_get(bn_ctx.get());
    REQUIRE(deser);
    REQUIRE(MtA::deserialise_inner_product(deser, b0, delta, size_of_each, q,
                                           bn_ctx.get()));

    // We'll also compute the inner product manually too.
    BIGNUM *tmp = BN_CTX_get(bn_ctx.get());
    BIGNUM *s1 = BN_CTX_get(bn_ctx.get());
    BIGNUM *man = BN_CTX_get(bn_ctx.get());
    REQUIRE(tmp);
    REQUIRE(s1);
    REQUIRE(man);

    for (unsigned i = 0; i < n; i++) {
      REQUIRE(BN_mod_mul(tmp, a_bignums[i], delta[i], q, bn_ctx.get()));
      REQUIRE(BN_mod_add(s1, man, tmp, q, bn_ctx.get()));
      REQUIRE(BN_copy(man, s1));
    }

    CHECK(BN_cmp(man, deser) == 0);
  }
}

//! [MtAProduceSenderPairs]
TEST_CASE("produce_sender_pairs") {
  // This tests that we get two serialised vectors
  // where the first contains ` -a + delta[i]` and the second contains
  // `a + delta[i]`.
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  static constexpr int prime_sizes[]{8, 16, 32, 64, 128, 256, 512};
  for (auto prime_size : prime_sizes) {
    // Generate a random prime to use as a modulus.
    BIGNUM *q = BN_CTX_get(bn_ctx.get());
    REQUIRE(q);
    // Last parameter means we'll use a safe prime. No real reason for this.
    REQUIRE(generate_n_bit_prime(q, prime_size, 1));
    // We'll generate a random `a` and a random vector of `deltas`.
    bssl::Array<BIGNUM *> delta;
    BIGNUM *a = BN_CTX_get(bn_ctx.get());
    REQUIRE(BN_rand_range_ex(a, 1, q));
    const auto n = MtA::k + BN_num_bits(q);
    const auto size_of_each = MtA::round_up_to_block(BN_num_bytes(q));
    REQUIRE(MtA::generate_random_vector(delta, n, *q, *bn_ctx.get()));
    PackArray add_pack, sub_pack;
    REQUIRE(MtA::produce_sender_pairs(delta, a, size_of_each, add_pack,
                                      sub_pack, q, bn_ctx.get()));
    // Now we've produced the sender pairs, we'll iterate over each array,
    // deserialise each element and check that the values are what we'd
    // expect.
    BIGNUM *tmp = BN_CTX_get(bn_ctx.get());
    BIGNUM *diff = BN_CTX_get(bn_ctx.get());
    REQUIRE(tmp);
    REQUIRE(diff);

    uint8_t *add_curr = add_pack.data();
    uint8_t *sub_curr = sub_pack.data();

    for (unsigned i = 0; i < delta.size(); i++) {
      // Each delta is uniformly random, so we need to check that each entry
      // in `add_pack` and `sub_pack` decode properly.
      REQUIRE(BN_bin2bn(add_curr, size_of_each, tmp));
      add_curr += size_of_each;
      REQUIRE(BN_mod_add(diff, delta[i], a, q, bn_ctx.get()));
      CHECK(BN_cmp(diff, tmp) == 0);

      REQUIRE(BN_bin2bn(sub_curr, size_of_each, tmp));
      sub_curr += size_of_each;
      REQUIRE(BN_mod_sub(diff, delta[i], a, q, bn_ctx.get()));
      CHECK(BN_cmp(diff, tmp) == 0);
    }
  }
}

//! [MtAProduceSenderPairs]

//! [MtAOtPreReqs]
TEST_CASE("ot_pre_reqs") {
  EmpBlockOwningSpan r1(5);
  EmpBlockOwningSpan r2(4);

  bssl::Array<bool> choices;
  REQUIRE(choices.Init(3));

  // We also don't allow mismatched sizes.
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);

  bssl::UniquePtr<SSL> ssl{SSL_new(context.get())};
  REQUIRE(ssl);  

  SUBCASE("Mismatched sizes fail") {
    CHECK(!MtA::sender_ot(ssl.get(), r1, r2));
    CHECK(!MtA::receiver_ot(ssl.get(), r1, choices));
    CHECK(!MtA::receiver_ot(ssl.get(), r2, choices));
  }

  SUBCASE("Zero-sized entries fail") {
    EmpBlockOwningSpan r3, r4;
    bssl::Array<bool> empty_choices;
    REQUIRE(r3.size() == 0);
    REQUIRE(r4.size() == 0);
    REQUIRE(empty_choices.size() == 0);
    CHECK(!MtA::sender_ot(ssl.get(), r3, r4));
    CHECK(!MtA::receiver_ot(ssl.get(), r3, empty_choices));
  }
}
//! [MtAOtPreReqs]

//! [MtASenderOT]
TEST_CASE("sender_ot") {
  // This function just tests that we can, in fact, do the sender oblivious
  // transfer. This requires us to use SSL things, similarly to in
  // EmpWrapper.t.cpp
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);

  constexpr auto prime_size = 512;

  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  // We'll generate random blocks of data to exchange.
  // Generate a random prime to use as a modulus.
  BIGNUM *q = BN_CTX_get(bn_ctx.get());
  REQUIRE(q);
  // Last parameter means we'll use a safe prime. No real reason for this.
  REQUIRE(generate_n_bit_prime(q, prime_size, 1));
  // We'll generate a random `a` and a random vector of `deltas`.
  bssl::Array<BIGNUM *> delta;
  BIGNUM *a = BN_CTX_get(bn_ctx.get());
  REQUIRE(BN_rand_range_ex(a, 1, q));
  const auto n = (MtA::k) + BN_num_bits(q);
  const auto size_of_each = MtA::round_up_to_block(BN_num_bytes(q));
  REQUIRE(MtA::generate_random_vector(delta, n, *q, *bn_ctx.get()));
  PackArray add_pack, sub_pack;
  REQUIRE(MtA::produce_sender_pairs(delta, a, size_of_each, add_pack, sub_pack,
                                    q, bn_ctx.get()));
  // Now we have to convert those into blocks.
  auto b0(MtA::convert_arr_to_block(sub_pack));
  auto b1(MtA::convert_arr_to_block(add_pack));
  REQUIRE(b0.data());
  REQUIRE(b1.data());

  // We'll generate random entries for this test.
  //  Those random entries will later
  // be expanded because of a quirk of how EMP packages its messages.
  bssl::Array<bool> choices;
  REQUIRE(choices.Init(n));
  for (unsigned i = 0; i < n; i++) {
    choices[i] = rand();
  }

  bssl::Array<bool> expanded_choices;
  REQUIRE(MtA::expand_t_to_ot_width(size_of_each, choices, expanded_choices));
  // Conceptually we should have a choice for each block.
  REQUIRE(expanded_choices.size() == n * (size_of_each / sizeof(emp::block)));

  // Now we'll do the sender's oblivious transfer. To do that, though,
  // we need to also create a socket for the sender to use.
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
    CHECK(MtA::sender_ot(sender.get_ssl_object(), b0, b1));
  };

  // Now we'll set up the receiver.
  TLSSocket receiver_socket{context.get(), false};
  REQUIRE(receiver_socket.is_ssl_valid());
  std::thread t(sender_code);
  REQUIRE(receiver_socket.set_ip_v4());
  REQUIRE(receiver_socket.connect_to("127.0.0.1", port));
  // And finally we'll do the receiver's ot.
  EmpBlockOwningSpan r(expanded_choices.size());
  REQUIRE(
      MtA::receiver_ot(receiver_socket.get_ssl_object(), r, expanded_choices));

  // Now we've received them, we'll _just_ check they were what we sent
  // here.
  for (unsigned i = 0; i < expanded_choices.size(); i++) {
    if (expanded_choices[i]) {
      CHECK(emp::cmpBlock(&r[i], &b1[i], 1));
    } else {
      CHECK(emp::cmpBlock(&r[i], &b0[i], 1));
    }
  }

  // We need to join the sender's thread, otherwise we'll get a failure
  // when this test terminates.
  t.join();
}

TEST_CASE("mta_no_ot") {
  // This test case is just to make sure that an MtA without the oblivious
  // transfer works.
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope sscope(bn_ctx.get());
  // Firstly, we generate two random big numbers mod some prime. These are our
  // points on the curve.
  BIGNUM *a_x = BN_CTX_get(bn_ctx.get());
  BIGNUM *b_x = BN_CTX_get(bn_ctx.get());
  BIGNUM *sigma = BN_CTX_get(bn_ctx.get());

  BIGNUM *a_y = BN_CTX_get(bn_ctx.get());
  BIGNUM *b_y = BN_CTX_get(bn_ctx.get());

  REQUIRE(a_x);
  REQUIRE(b_x);
  REQUIRE(a_y);
  REQUIRE(b_y);

  constexpr auto curve_id = SSL_CURVE_SECP256R1;

  bssl::UniquePtr<EC_GROUP> group(
      EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve_id)));

  REQUIRE(group);
  const BIGNUM *const q = EC_GROUP_get0_order(group.get());

  REQUIRE(BN_rand_range_ex(a_x, 1, q));
  REQUIRE(BN_rand_range_ex(b_x, 1, q));

  // Now we'll turn the x co-ords into EC points.
  bssl::UniquePtr<EC_POINT> a_point(EC_POINT_new(group.get()));
  bssl::UniquePtr<EC_POINT> b_point(EC_POINT_new(group.get()));
  REQUIRE(a_point);
  REQUIRE(b_point);

  REQUIRE(
      EC_POINT_mul(group.get(), a_point.get(), a_x, NULL, NULL, bn_ctx.get()));
  REQUIRE(
      EC_POINT_mul(group.get(), b_point.get(), b_x, NULL, NULL, bn_ctx.get()));

  // Now we'll dump out the co-ordinates back down to affine co-ords.
  REQUIRE(EC_POINT_get_affine_coordinates_GFp(group.get(), a_point.get(), NULL,
                                              a_y, bn_ctx.get()));
  REQUIRE(EC_POINT_get_affine_coordinates_GFp(group.get(), b_point.get(), NULL,
                                              b_y, bn_ctx.get()));

  const auto n = BN_num_bits(q) + MtA::k;
  // Now we'll generate a random collection of bignums. This is the `delta`
  // array that the sender generates.
  bssl::Array<BIGNUM *> delta;
  REQUIRE(MtA::generate_random_vector(delta, n, *q, *bn_ctx.get()));

  // Now we'll generate something the receiver makes: the `t` and `v` arrays.
  bssl::Array<bool> t;
  bssl::Array<BIGNUM *> v;
  REQUIRE(MtA::generate_t_and_v(*b_y, *q, t, v, *bn_ctx.get()));
  REQUIRE(t.size() == n);
  // We'll also generate sigma, which is for correctness.
  REQUIRE(BN_rand_range_ex(sigma, 1, q));

  // The sender computes -<v, delta> - sigma
  BIGNUM *curr = BN_CTX_get(bn_ctx.get());
  BIGNUM *s1 = BN_CTX_get(bn_ctx.get());
  BIGNUM *zero = BN_CTX_get(bn_ctx.get());
  BIGNUM *tmp = BN_CTX_get(bn_ctx.get());

  REQUIRE(s1);
  REQUIRE(curr);
  REQUIRE(zero);
  REQUIRE(tmp);

  // This corresponds to the sender's share computation.
  // Essentially, we compute <v, delta> here, then we compute
  // -<v, delta>, and finally -<v, delta> - sigma
  for (unsigned i = 0; i < n; i++) {
    REQUIRE(BN_mod_mul(curr, v[i], delta[i], q, bn_ctx.get()));
    REQUIRE(BN_mod_add(tmp, s1, curr, q, bn_ctx.get()));
    REQUIRE(BN_copy(s1, tmp));
  }

  REQUIRE(BN_mod_sub(tmp, zero, s1, q, bn_ctx.get()));
  REQUIRE(BN_mod_sub(s1, tmp, sigma, q, bn_ctx.get()));

  // With the receiver, they compute:
  // delta[i] - `a_y` if t[i] == 0
  // delta[i] + `a_y` if t[i] == 1

  // Note: to simulate this case more effectively, we're going to
  // produce the sender's pairs and use those (just to make sure it works).
  PackArray add_pack, sub_pack;
  const auto size_of_each = MtA::round_up_to_block(BN_num_bytes(q));
  REQUIRE(MtA::produce_sender_pairs(delta, a_y, size_of_each, add_pack,
                                    sub_pack, q, bn_ctx.get()));

  const auto b0 = MtA::convert_arr_to_block(sub_pack);
  const auto b1 = MtA::convert_arr_to_block(add_pack);
  REQUIRE(b0.data());
  REQUIRE(b1.data());

  // Now we'll simulate the OT. To do this, we'll expand out `t` to the right
  // size and then manually do the OT. This, obviously, isn't how this would
  // happen over sockets.
  bssl::Array<bool> t_expanded;
  REQUIRE(MtA::expand_t_to_ot_width(size_of_each, t, t_expanded));
  EmpBlockOwningSpan z(t_expanded.size());
  for (unsigned i = 0; i < t_expanded.size(); i++) {
    z[i] = (t_expanded[i]) ? b1[i] : b0[i];
  }

  // With those z's, we should compute the inner product of `z` and `v`.
  BIGNUM *s2 = BN_CTX_get(bn_ctx.get());
  const uint8_t *curr_ptr = reinterpret_cast<uint8_t *>(z.data());
  REQUIRE(s2);
  for (unsigned i = 0; i < n; i++) {
    REQUIRE(BN_bin2bn(curr_ptr, size_of_each, tmp));
    curr_ptr += size_of_each;
    REQUIRE(BN_mod_mul(curr, tmp, v[i], q, bn_ctx.get()));
    REQUIRE(BN_mod_add(tmp, s2, curr, q, bn_ctx.get()));
    REQUIRE(BN_copy(s2, tmp));
  }

  // And finally, we'll add back sigma.
  REQUIRE(BN_mod_add(s2, tmp, sigma, q, bn_ctx.get()));

  // And now we'll check that s2 + s1 (mod q) == a * b.
  BIGNUM *prod = BN_CTX_get(bn_ctx.get());
  BIGNUM *sum = BN_CTX_get(bn_ctx.get());
  REQUIRE(prod);
  REQUIRE(sum);

  REQUIRE(BN_mod_add(sum, s1, s2, q, bn_ctx.get()));
  REQUIRE(BN_mod_mul(prod, a_y, b_y, q, bn_ctx.get()));
  CHECK(BN_cmp(sum, prod) == 0);
}

//! [MtAIEFS]
TEST_CASE("IEFS") {
  // This function checks that we can initialise the
  // sender's variables as expected.
  static constexpr unsigned prime_size = 256;
  static constexpr unsigned n = prime_size + MtA::k;

  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  BIGNUM *q = BN_CTX_get(bn_ctx.get());
  REQUIRE(q);
  REQUIRE(generate_n_bit_prime(q, prime_size, 1));

  SenderEntry se{};

  SUBCASE("nullptrs cause failure") {
    CHECK(!MtA::initialise_entries_for_sender(n, nullptr, se, nullptr));
    CHECK(!MtA::initialise_entries_for_sender(n, nullptr, se, bn_ctx.get()));
    CHECK(!MtA::initialise_entries_for_sender(n, q, se, nullptr));
  }

  SUBCASE("otherwise works") {
    CHECK(MtA::initialise_entries_for_sender(n, q, se, bn_ctx.get()));

    REQUIRE(se.delta.size() == n);
    for (unsigned i = 0; i < n; i++) {
      CHECK(BN_cmp(se.delta[i], q) < 0);
    }

    const auto size_of_each = MtA::round_up_to_block(BN_num_bytes(q));
    CHECK(se.add_pack.size() == size_of_each * n);
    CHECK(se.sub_pack.size() == size_of_each * n);
    CHECK(se.vals.size() == n * size_of_each);
    CHECK(se.sigma_v.size() == size_of_each);
  }
}
//! [MtAIEFS]

//! [MtAIERS]
TEST_CASE("IERS") {
  // This function checks that we can initialise the
  // receivers's variables as expected.
  static constexpr unsigned prime_size = 256;
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  BIGNUM *q = BN_CTX_get(bn_ctx.get());
  REQUIRE(q);
  REQUIRE(generate_n_bit_prime(q, prime_size, 1));

  ReceiverEntry re{};

  SUBCASE("nullptrs cause failure") {
    CHECK(!MtA::initialise_entries_for_receiver(nullptr, re, nullptr));
    CHECK(!MtA::initialise_entries_for_receiver(nullptr, re, bn_ctx.get()));
    CHECK(!MtA::initialise_entries_for_receiver(q, re, nullptr));
  }

  SUBCASE("otherwise works") {
    CHECK(MtA::initialise_entries_for_receiver(q, re, bn_ctx.get()));

    const auto n = BN_num_bits(q) + MtA::k;
    CHECK(re.t.size() == n);
    const auto size_of_each = MtA::round_up_to_block(BN_num_bytes(q));
    CHECK(re.t_extended.size() == n * size_of_each / sizeof(emp::block));
    REQUIRE(re.v.size() == n);
    for (auto v_i : re.v) {
      CHECK(BN_cmp(v_i, q) < 0);
    }

    CHECK(re.v_serialised.size() == re.v.size() * size_of_each);
    CHECK(re.sigma_serialised.size() == size_of_each);
    CHECK(re.z.size() == re.t_extended.size());
  }
}
//! [MtAIERS]

//! [MtADoOT]
TEST_CASE("do_ot") {
  // We'll now do a full OT, over sockets, but with
  // a single curve.

  // Idea: we generate two random points on a NIST curve and
  // check that we can decompose them.
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);
  bssl::UniquePtr<BN_CTX> sbn_ctx(BN_CTX_new());
  REQUIRE(sbn_ctx);
  bssl::BN_CTXScope sscope(sbn_ctx.get());

  bssl::UniquePtr<BN_CTX> rbn_ctx(BN_CTX_new());
  REQUIRE(rbn_ctx);
  bssl::BN_CTXScope rscope(rbn_ctx.get());

  constexpr auto curve_id = SSL_CURVE_SECP256R1;

  bssl::UniquePtr<EC_GROUP> sgroup(
      EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve_id))),
      rgroup(EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve_id)));
  REQUIRE(sgroup);
  REQUIRE(rgroup);
  REQUIRE(EC_GROUP_cmp(sgroup.get(), rgroup.get(), nullptr) == 0);

  BIGNUM *rbig = BN_CTX_get(rbn_ctx.get());
  BIGNUM *sbig = BN_CTX_get(sbn_ctx.get());
  REQUIRE(rbig);
  REQUIRE(sbig);

  REQUIRE(BN_rand_range_ex(rbig, 1, EC_GROUP_get0_order(rgroup.get())));
  REQUIRE(BN_rand_range_ex(sbig, 1, EC_GROUP_get0_order(sgroup.get())));

  bssl::UniquePtr<EC_POINT> rpoint(EC_POINT_new(rgroup.get()));
  bssl::UniquePtr<EC_POINT> spoint(EC_POINT_new(sgroup.get()));
  REQUIRE(rpoint);
  REQUIRE(spoint);

  REQUIRE(EC_POINT_mul(rgroup.get(), rpoint.get(), rbig, NULL, NULL,
                       rbn_ctx.get()));
  REQUIRE(EC_POINT_mul(sgroup.get(), spoint.get(), sbig, NULL, NULL,
                       sbn_ctx.get()));

  BIGNUM *ry = BN_CTX_get(rbn_ctx.get());
  BIGNUM *sy = BN_CTX_get(sbn_ctx.get());
  REQUIRE(ry);
  REQUIRE(sy);

  REQUIRE(EC_POINT_get_affine_coordinates_GFp(rgroup.get(), rpoint.get(), NULL,
                                              ry, rbn_ctx.get()));
  REQUIRE(EC_POINT_get_affine_coordinates_GFp(sgroup.get(), spoint.get(), NULL,
                                              sy, sbn_ctx.get()));

  // Now decompose.
  BIGNUM *rout = BN_CTX_get(rbn_ctx.get());
  std::mutex m;
  BIGNUM *sout = BN_CTX_get(sbn_ctx.get());
  REQUIRE(rout);
  REQUIRE(sout);

  // Now we'll set up each connection.
  TLSSocket sender{context.get()};
  uint16_t port;
  REQUIRE(sender.set_ip_v4());
  REQUIRE(sender.set_addr("127.0.0.1"));
  REQUIRE(sender.bind());
  REQUIRE(sender.listen(1));
  REQUIRE(sender.get_portnumber(&port));

  // We'll do the connection and the OT in one move.
  const auto sender_join_code = [&]() {
    REQUIRE(sender.accept());
    REQUIRE(sender.do_handshake() == 1);
    std::scoped_lock<std::mutex> lock(m);
    EmpWrapper<> wrapper{sender.get_ssl_object()};
    emp::IKNP<EmpWrapper<>> ot(&wrapper, true);
    REQUIRE(
        MtA::play_sender(sout, ot, sy,
                         EC_GROUP_get0_order(sgroup.get()), sbn_ctx.get()));
  };

  std::thread t(sender_join_code);
  // Now we need to set-up the receiver.
  {
    TLSSocket receiver_socket{context.get(), false};
    REQUIRE(receiver_socket.is_ssl_valid());
    REQUIRE(receiver_socket.set_ip_v4());
    REQUIRE(receiver_socket.connect_to("127.0.0.1", port));
    EmpWrapper<> wrapper{receiver_socket.get_ssl_object()};
    emp::IKNP<EmpWrapper<>> ot(&wrapper, true);
    REQUIRE(MtA::play_receiver(rout, ot, ry,
                               EC_GROUP_get0_order(rgroup.get()),
                               rbn_ctx.get()));
  }
  // We'll now join `t`, since the protocol has finished.
  t.join();

  std::scoped_lock<std::mutex> lock(m);
  REQUIRE(BN_cmp(rout, EC_GROUP_get0_order(rgroup.get())) < 0);
  REQUIRE(BN_cmp(sout, EC_GROUP_get0_order(sgroup.get())) < 0);
  REQUIRE(BN_cmp(ry, EC_GROUP_get0_order(rgroup.get())) < 0);
  REQUIRE(BN_cmp(sy, EC_GROUP_get0_order(sgroup.get())) < 0);

  // And finally we want to check that rout + sout == ry * sy.
  // To do that, we do the multiplication of the curve points, but treating
  // ry and sy as elements modulo EC_GROUP_get0_order.
  BIGNUM *out = BN_CTX_get(rbn_ctx.get());
  BIGNUM *sum = BN_CTX_get(rbn_ctx.get());
  REQUIRE(out);
  REQUIRE(sum);
  REQUIRE(BN_mod_mul(out, ry, sy, EC_GROUP_get0_order(rgroup.get()),
                     rbn_ctx.get()));
  REQUIRE(BN_mod_add(sum, rout, sout, EC_GROUP_get0_order(rgroup.get()),
                     rbn_ctx.get()));
  CHECK(BN_cmp(out, sum) == 0);
}
//! [MtADoOT]

//! [MtAFullOT]
TEST_CASE("full_ot") {
  // This is a test case in getting the full MtA working.
  // Essentially, we generate two random elliptic curve points (alpha, beta)
  // and check that we get two output bignums (a,b) such that a + b = alpha *
  // beta.

  // First of all, we do this over TLS.
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);

  // Before we get back to the TLS stuff, we'll set up our arithmetic.
  // Each party has their own world of bignums to do work, plus predefined
  // groups and curves.
  constexpr auto nr_curves = 4;
  static constexpr uint16_t curves[]{SSL_CURVE_SECP224R1, SSL_CURVE_SECP256R1,
                                     SSL_CURVE_SECP384R1, SSL_CURVE_SECP521R1};
  REQUIRE(sizeof(curves) / sizeof(uint16_t) == nr_curves);

  // NOTE: what follows is an un-neat way of grouping the various
  // experimental bits of data together. This is primarily to reduce code
  // duplication.
  struct ExpermSet {
    bssl::UniquePtr<BN_CTX> ctx;
    bssl::BN_CTXScope scope;
    std::array<bssl::UniquePtr<EC_GROUP>, nr_curves> groups;
    std::array<bssl::UniquePtr<EC_POINT>, nr_curves> points;
    std::array<bssl::UniquePtr<BIGNUM>, nr_curves> coords;
    std::array<bssl::UniquePtr<BIGNUM>, nr_curves> y_coords;

    std::array<bssl::UniquePtr<BIGNUM>, nr_curves> recv;

    ExpermSet()
        : ctx(BN_CTX_new()), scope{ctx.get()}, groups{}, points{}, coords{},
          y_coords{}, recv{} {}

    ExpermSet(ExpermSet &&other)
        : ctx(std::move(other.ctx)),
          scope(ctx.get()), groups{std::move(other.groups)},
          points{std::move(other.points)}, coords{std::move(other.coords)},
          y_coords{std::move(other.y_coords)}, recv{std::move(other.recv)} {}
  };

  // This lambda builds an ExpermSet for the caller. Each call returns
  // a unique instance.
  auto build_experm = [&]() {
    ExpermSet set;
    REQUIRE(set.ctx);
    for (unsigned i = 0; i < set.groups.size(); i++) {
      set.groups[i].reset(
          EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curves[i])));
      REQUIRE(set.groups[i]);
      set.coords[i].reset(BN_CTX_get(set.ctx.get()));
      REQUIRE(set.coords[i]);
      REQUIRE(BN_rand_range_ex(set.coords[i].get(), 1,
                               EC_GROUP_get0_order(set.groups[i].get())));
      set.points[i].reset(EC_POINT_new(set.groups[i].get()));
      REQUIRE(set.points[i]);
      set.y_coords[i].reset(BN_CTX_get(set.ctx.get()));
      REQUIRE(set.y_coords[i]);
      REQUIRE(EC_POINT_mul(set.groups[i].get(), set.points[i].get(),
                           set.coords[i].get(), NULL, NULL, set.ctx.get()));
      REQUIRE(EC_POINT_get_affine_coordinates_GFp(
          set.groups[i].get(), set.points[i].get(), NULL, set.y_coords[i].get(),
          set.ctx.get()));
      set.recv[i].reset(BN_CTX_get(set.ctx.get()));
      REQUIRE(set.recv[i]);
    }
    return set;
  };

  auto sender_set = build_experm();
  auto receiver_set = build_experm();

  // Now we'll set up each connection.
  TLSSocket sender{context.get()};
  uint16_t port;
  REQUIRE(sender.set_ip_v4());
  REQUIRE(sender.set_addr("127.0.0.1"));
  REQUIRE(sender.bind());
  REQUIRE(sender.listen(1));
  REQUIRE(sender.get_portnumber(&port));

  // We'll do the connection once for the whole set of tests.
  const auto sender_join_code = [&]() {
    REQUIRE(sender.accept());
    REQUIRE(sender.do_handshake() == 1);
  };

  std::thread t(sender_join_code);

  // Now we need to set-up the receiver.
  TLSSocket receiver_socket{context.get(), false};
  REQUIRE(receiver_socket.is_ssl_valid());
  REQUIRE(receiver_socket.set_ip_v4());
  REQUIRE(receiver_socket.connect_to("127.0.0.1", port));

  // We'll now join `t`, since the connection is established.
  t.join();

  // This lambda just accepts a pack, an instance `i` and
  // runs either the sender's code or the receiver's code, depending
  // on the final parameter. This is just to make the loop slightly shorter.
  auto op_code = [&](unsigned i, SSL *const ssl, ExpermSet &set,
                     bool is_sender) {
    if (is_sender) {
      EmpWrapper<> wrapper{ssl};
      emp::IKNP<EmpWrapper<>> ot(&wrapper, true);
      REQUIRE(MtA::play_sender(set.recv[i].get(), ot, set.y_coords[i].get(),
                           EC_GROUP_get0_order(set.groups[i].get()),
                           set.ctx.get()));
    } else {
      EmpWrapper<> wrapper{ssl};
      emp::IKNP<EmpWrapper<>> ot(&wrapper, true);
      REQUIRE(MtA::play_receiver(set.recv[i].get(), ot, set.y_coords[i].get(),
                                 EC_GROUP_get0_order(set.groups[i].get()),
                                 set.ctx.get()));
    }
  };

  for (unsigned i = 0; i < nr_curves; i++) {
    // N.B this thread runs another lambda to make the argument passing
    // easier.
    std::thread sender_thread(
        [&] { op_code(i, sender.get_ssl_object(), sender_set, true); });

    // We'll run the receiver's code on this thread.
    op_code(i, receiver_socket.get_ssl_object(), receiver_set, false);

    // And now we'll end the sender's routine.
    sender_thread.join();

    // Now check that the sum of the elements are as expected.
    BIGNUM *out = BN_CTX_get(sender_set.ctx.get());
    BIGNUM *sum = BN_CTX_get(receiver_set.ctx.get());
    REQUIRE(out);
    REQUIRE(sum);
    REQUIRE(BN_mod_mul(out, receiver_set.y_coords[i].get(),
                       sender_set.y_coords[i].get(),
                       EC_GROUP_get0_order(receiver_set.groups[i].get()),
                       receiver_set.ctx.get()));
    REQUIRE(BN_mod_add(sum, receiver_set.recv[i].get(),
                       sender_set.recv[i].get(),
                       EC_GROUP_get0_order(receiver_set.groups[i].get()),
                       receiver_set.ctx.get()));
    CHECK(BN_cmp(out, sum) == 0);
  }
}
//! [MtAFullOT]

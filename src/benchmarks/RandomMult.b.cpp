// This benchmark file is meant to test the following hypothesis:
// Is it faster to branch or multiply by 0/1 when using BoringSSL's Bignum
// library? This is mentioned in Mta/Encode.cpp's Encode::Encode function

// In other words, in this file we derive costs for computing the inner product
// of two vectors, a and b. Here:
// 1. a is a random vector comprised of elements mod `q`
// 2. b is a binary vector.
// Since we do component-wise multiplication for inner products, we can either
// compute the inner product normally, or we can branch on each element of `b`
// and simply add a[i] to the total if `b[i]` ==  1.
// It isn't clear which one is faster, so this benchmark should help work it
// out.

// We parameterise on:
// 1) The modulus (e.g the `q` in the group Z_q)
// 2) The bitsize of each element a[i].
// 3) The length of a and b.
//
// This benchmark suffers from the same limitations as other microbenchmarks
// (e.g caching performs well on microbenchmarks)
#include "../mta/Encode.hpp" // Needed for generating random vectors and random bitstrings.
#include <benchmark/benchmark.h> // Needed for all benchmarking stuff.

static void BM_multiply_no_branch(benchmark::State &state) {
  // First of all we'll extract the parameters.
  // We pack these as:
  // 1. Modulus size first.
  // 2. Bitsize second.
  // 3. Vector size third.

  const auto q = static_cast<unsigned>(state.range(0));
  const auto l = static_cast<uint64_t>(state.range(1));
  const auto k = static_cast<uint64_t>(state.range(2));

  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  bssl::BN_CTXScope scope(bn_ctx.get());

  // Now we'll generate the arrays.
  bssl::Array<BIGNUM *> a, b;
  Encode::generate_random_bitstring(k, *bn_ctx.get(), b);
  Encode::generate_random_vector(a, k, l, q, *bn_ctx.get());

  // And finally we'll create a bignum to hold the result.
  BIGNUM *total = BN_CTX_get(bn_ctx.get());
  BIGNUM *intermediate = BN_CTX_get(bn_ctx.get());
  BIGNUM *q_as_bn = BN_CTX_get(bn_ctx.get());
  BN_set_u64(q_as_bn, q);

  // To erode the noise from the getter, we'll extract the context.
  auto *ctx = bn_ctx.get();

  // So now we'll multiply them all together.
  for (auto _ : state) {
    // NOTE: this is included in the benchmarking, but every loop has to do
    // this to stop the bitsize getting too large.
    BN_zero(total);
    for (unsigned i = 0; i < k; i++) {
      // Multiply them.
      BN_mod_mul(intermediate, b[i], a[i], q_as_bn, ctx);
      // And add
      BN_mod_add(total, total, intermediate, q_as_bn, ctx);
    }
    // Make sure that total actually gets computed.
    benchmark::DoNotOptimize(total);
  }
}

static void BM_multiply_branch(benchmark::State &state) {
  // First of all we'll extract the parameters.
  // We pack these as:
  // 1. Modulus size first.
  // 2. Bitsize second.
  // 3. Vector size third.

  const auto q = static_cast<unsigned>(state.range(0));
  const auto l = static_cast<uint64_t>(state.range(1));
  const auto k = static_cast<uint64_t>(state.range(2));

  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  bssl::BN_CTXScope scope(bn_ctx.get());

  // Now we'll generate the arrays.
  bssl::Array<BIGNUM *> a, b;
  Encode::generate_random_bitstring(k, *bn_ctx.get(), b);
  Encode::generate_random_vector(a, k, l, q, *bn_ctx.get());

  // And finally we'll create a bignum to hold the result.
  BIGNUM *total = BN_CTX_get(bn_ctx.get());
  BIGNUM *q_as_bn = BN_CTX_get(bn_ctx.get());
  BN_set_u64(q_as_bn, q);

  // To erode the noise from the getter, we'll extract the context.
  auto *ctx = bn_ctx.get();

  // So now we'll multiply them all together.
  for (auto _ : state) {
    // NOTE: this is included in the benchmarking, but every loop has to do
    // this to stop the bitsize getting too large.
    BN_zero(total);
    for (unsigned i = 0; i < k; i++) {
      // Branch and add.
      if (BN_is_one(b[i])) {
        // And add
        BN_mod_add(total, total, a[i], q_as_bn, ctx);
      }
    }
    // Make sure that total actually gets computed.
    benchmark::DoNotOptimize(total);
  }
}

static void generate_args(benchmark::internal::Benchmark *b) {
  constexpr static int primes[]{2, 3};
  constexpr static int bitsizes[]{32, 64, 128, 256};
  constexpr static int lengths[]{2, 4, 8, 16, 32};
  for (auto prime : primes) {
    for (auto bitsize : bitsizes) {
      for (auto length : lengths) {
        b->Args({prime, bitsize, length});
      }
    }
  }
}

BENCHMARK(BM_multiply_branch)->Apply(generate_args);
BENCHMARK(BM_multiply_no_branch)->Apply(generate_args);

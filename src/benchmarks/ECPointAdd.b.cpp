#include "../ssl/Util.hpp"       // Needed for utility functions
#include <benchmark/benchmark.h> // Needed for ... benchmarks.

// In this benchmark we generate two random
// elliptic curve points, convert them to
// CBB's and then test how long it takes to add them (with decoding).

// As a remark: this sort of microbenchmarking can be incredibly misleading
// when it comes to understanding performance of certain parts of a program
// when the overall program is actually running. It is our hope that these
// microbenchmarks might help us find problems later, if they appear.

// Note that this is primarily to test the speed of decoding: the actual
// arithmetic should be far faster. To show this fact, we also include a
// benchmark without the serialisation.

static void BM_ECPointAdditionWithSerialisation(benchmark::State &state) {
  const uint16_t group_id = static_cast<uint16_t>(state.range(0));
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  bssl::BN_CTXScope scope(bn_ctx.get());
  bssl::UniquePtr<EC_GROUP> group(
      EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(group_id)));

  bssl::UniquePtr<EC_POINT> a(EC_POINT_new(group.get())),
      b(EC_POINT_new(group.get())), c(EC_POINT_new(group.get()));
  Util::RandomECPoint(group.get(), a.get(), bn_ctx.get());
  Util::RandomECPoint(group.get(), b.get(), bn_ctx.get());

  bssl::Array<uint8_t> a_arr, b_arr;
  Util::ECPointToCBB(group_id, group.get(), a.get(), a_arr, bn_ctx.get());
  Util::ECPointToCBB(group_id, group.get(), b.get(), b_arr, bn_ctx.get());

  for (auto _ : state) {
    // Must be non-const to make everything work happily.
    auto res = Util::EC_point_addition(group.get(), &c, a_arr, b_arr, bn_ctx.get());
    benchmark::DoNotOptimize(res);
  }
}

static void BM_ECPointAdditionNoSerialisation(benchmark::State &state) {
  const uint16_t group_id = static_cast<uint16_t>(state.range(0));
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  bssl::BN_CTXScope scope(bn_ctx.get());
  bssl::UniquePtr<EC_GROUP> group(
      EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(group_id)));
  bssl::UniquePtr<EC_POINT> a(EC_POINT_new(group.get())),
      b(EC_POINT_new(group.get())), c(EC_POINT_new(group.get()));
  Util::RandomECPoint(group.get(), a.get(), bn_ctx.get());
  Util::RandomECPoint(group.get(), b.get(), bn_ctx.get());

  for (auto _ : state) {
    // Must be non-const to make everything work happily.
    auto res = EC_POINT_add(group.get(), c.get(), a.get(), b.get(), bn_ctx.get());
    benchmark::DoNotOptimize(res);
  }
}

BENCHMARK(BM_ECPointAdditionWithSerialisation)
    ->Args({SSL_CURVE_SECP224R1})
    ->Args({SSL_CURVE_SECP256R1})
    ->Args({SSL_CURVE_SECP384R1})
    ->Args({SSL_CURVE_SECP521R1});

BENCHMARK(BM_ECPointAdditionNoSerialisation)
    ->Args({SSL_CURVE_SECP224R1})
    ->Args({SSL_CURVE_SECP256R1})
    ->Args({SSL_CURVE_SECP384R1})
    ->Args({SSL_CURVE_SECP521R1});

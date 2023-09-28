#include "../mta/MtA.hpp"
#include "../ssl/TLSSocket.hpp"
#include "../ssl/TestUtil.hpp"
#include <benchmark/benchmark.h>
#include <thread>

// This benchmark tries to measure the cost of doing a single MtA
// over TLS. 
static void BM_mta(benchmark::State &state) {
  state.PauseTiming(); // Don't time TLS setup.
  auto context = CreateContextWithTestCertificate(TLS_method());
  const uint16_t curve = static_cast<uint16_t>(state.range(0));

  // Setup TLS stuff.
  TLSSocket sender{context.get()};
  uint16_t port;

  if (!sender.set_ip_v4()) {
    std::cerr << "Sender could not set ipv4" << std::endl;
  }

  if (!sender.set_addr("127.0.0.1")) {
    std::cerr << "Sender could not set addr" << std::endl;
  }

  if (!sender.bind()) {
    std::cerr << "Sender could not bind" << std::endl;
  }

  if (!sender.listen(1)) {
    std::cerr << "Sender could not listen" << std::endl;
  }

  if (!sender.get_portnumber(&port)) {
    std::cerr << "Sender could not get port" << std::endl;
  }

  const auto sender_join_code = [&]() {
    if (!sender.accept()) {
      std::cerr << "Failed to do accept" << std::endl;
    }

    if (sender.do_handshake() != 1) {
      std::cerr << "Failed to do handshake" << std::endl;
    }
  };

  std::thread t(sender_join_code);
  TLSSocket receiver{context.get(), false};
  if (!receiver.set_ip_v4()) {
    std::cerr << "Receiver could not set ipv4" << std::endl;
  }

  if (!receiver.connect_to("127.0.0.1", port)) {
    std::cerr << "Receiver could not connect" << std::endl;
  }

  t.join();

  bssl::UniquePtr<BN_CTX> rbn_ctx(BN_CTX_new());
  bssl::BN_CTXScope rscope(rbn_ctx.get());

  // Now generate the other parts.
  bssl::UniquePtr<EC_GROUP> group(
      EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve)));
  BIGNUM *receiver_point = BN_CTX_get(rbn_ctx.get());

  BN_rand_range_ex(receiver_point, 1, EC_GROUP_get0_order(group.get()));
  BIGNUM *receiver_out = BN_CTX_get(rbn_ctx.get());

  std::atomic<bool> still_going = true;

  EmpWrapper<> sender_wrapper { sender.get_ssl_object() };
  EmpWrapper<> receiver_wrapper { receiver.get_ssl_object() };
  emp::IKNP<EmpWrapper<>> sender_ot(&sender_wrapper, true);
  emp::IKNP<EmpWrapper<>> receiver_ot(&receiver_wrapper, true);
  
  auto sender_code = [&]() {
    // This needs to be all done in its own thread: otherwise, the destructors
    // will be in a race condition when not using ASAN.
    bssl::UniquePtr<BN_CTX> sbn_ctx(BN_CTX_new());
    bssl::BN_CTXScope sscope(sbn_ctx.get());
    BIGNUM *sender_point = BN_CTX_get(sbn_ctx.get());
    BIGNUM *sender_out = BN_CTX_get(sbn_ctx.get());
    BN_rand_range_ex(sender_point, 1, EC_GROUP_get0_order(group.get()));

    while (still_going) {
      MtA::play_sender(sender_out, sender_ot, sender_point,
                       EC_GROUP_get0_order(group.get()), sbn_ctx.get());
    }
  };

  state.ResumeTiming();
  std::thread sender_thread(sender_code);

  for (auto _ : state) {
    MtA::play_receiver(receiver_out, receiver_ot, receiver_point,
                       EC_GROUP_get0_order(group.get()), rbn_ctx.get());
  }

  still_going = false;
  sender_thread.join();
}

BENCHMARK(BM_mta)
    ->Args({SSL_CURVE_SECP224R1})
    ->Args({SSL_CURVE_SECP256R1})
    ->Args({SSL_CURVE_SECP384R1})
    ->Args({SSL_CURVE_SECP521R1});

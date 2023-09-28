#include "../mta/F2128MtA.hpp"
#include "../ssl/TLSSocket.hpp"
#include "../ssl/TestUtil.hpp"
#include <benchmark/benchmark.h>
#include <thread>

// This benchmark tries to measure the cost of doing a
// full AES secret sharing over TLS.
// The actual instantiation of these benchmarks is in the struct below,
// which is designed to separate server and client initialisation. This is
// to allow you to run this over a network.
template <bool is_server> struct F2128_MTABench {
  // Set your server IP here!
  inline static const std::string server_ip = "192.168.1.179";

  // Set your desired port here!
  inline static constexpr uint16_t port_iknp_rep = 16000;
  inline static constexpr uint16_t port_ferret_rep = 16001;
  inline static constexpr uint16_t port_iknp_batch = 16002;
  inline static constexpr uint16_t port_ferret_batch = 16003;

  template <uint16_t port> static void connect(TLSSocket &socket) {
    if (is_server) {
      if (!socket.set_ip_v4()) {
        std::cerr << "Server could not set ipv4" << std::endl;
        std::abort();
      }

      if (!socket.set_addr(server_ip)) {
        std::cerr << "Server could not set addr" << std::endl;
        std::abort();
      }

      if (!socket.set_port(port)) {
        std::cerr << "Server could not set port" << std::endl;
        std::abort();
      }

      if (!socket.bind()) {
        std::cerr << "Server could not bind" << std::endl;
        std::abort();
      }

      if (!socket.listen(1)) {
        std::cerr << "Server could not listen" << std::endl;
        std::abort();
      }

      if (!socket.accept()) {
        std::cerr << "Server failed to do accept" << std::endl;
        std::abort();
      }

      if (socket.do_handshake() != 1) {
        std::cerr << "Server failed to do handshake" << std::endl;
        std::abort();
      }
    } else {
      if (!socket.set_ip_v4()) {
        std::cerr << "Receiver could not set ipv4" << std::endl;
        std::abort();
      }

      if (!socket.connect_to(server_ip, port)) {
        std::cerr << "Receiver could not connect" << std::endl;
        std::abort();
      }
    }
  }

  template <typename OTType>
  inline static void BM_batched(OTType &ot, SSL *socket,
                                benchmark::State &state,
                                const emp::block input) {
    state.ResumeTiming();
    uint64_t bandwidth{};
    for (auto _ : state) {
      // This code doesn't need to be wrapped in DoNotOptimize, as it
      // generates runtime events (i.e the call must happen).
      if constexpr (is_server) {
        F2128_MTA::generate_shares_verifier_batched(ot, *socket, input,
                                                    bandwidth);
      } else {
        F2128_MTA::generate_shares_prover_batched(ot, *socket, input,
                                                  bandwidth);
      }
    }
  }

  static void BM_batched_ferret(benchmark::State &state) {
    state.PauseTiming(); // Don't time the TLS session creation.
    auto context = CreateContextWithTestCertificate(TLS_method());
    TLSSocket socket{context.get(), is_server};
    connect<port_ferret_batch>(socket);

    // Generate a random input.
    emp::block input;
    Util::generate_random_bytes<sizeof(input)>(&input);

    // Use Ferret.
    EmpWrapper<> wrapper{socket.get_ssl_object()};
    EmpWrapper<> *as_arr[2]{&wrapper, &wrapper};
    emp::FerretCOT<EmpWrapper<>> ot(((is_server) ? emp::ALICE : emp::BOB), 1,
                                    as_arr, true, true);

    BM_batched(ot, socket.get_ssl_object(), state, input);
  }

  static void BM_batched_IKNP(benchmark::State &state) {
    state.PauseTiming(); // Don't time the TLS session creation.
    auto context = CreateContextWithTestCertificate(TLS_method());
    TLSSocket socket{context.get(), is_server};
    connect<port_iknp_batch>(socket);

    // Generate a random input.
    emp::block input;
    Util::generate_random_bytes<sizeof(input)>(&input);

    // Use IKNP.
    EmpWrapper<> wrapper{socket.get_ssl_object()};
    emp::IKNP<EmpWrapper<>> ot(&wrapper, true);
    BM_batched(ot, socket.get_ssl_object(), state, input);
  }

  template <typename OTType>
  static void BM_repeated(OTType &ot, SSL *ssl, benchmark::State &state,
                          const emp::block input) {
    state.ResumeTiming();
    for (auto _ : state) {
      // This code doesn't need to be wrapped in DoNotOptimize, as it
      // generates runtime events (i.e the call must happen).
      if constexpr (is_server) {
        F2128_MTA::generate_shares_verifier_repeated(ot, *ssl, input);
      } else {
        F2128_MTA::generate_shares_prover_repeated(ot, *ssl, input);
      }
    }
  }

  static void BM_repeated_ferret(benchmark::State &state) {
    state.PauseTiming(); // Don't time the TLS session creation.
    auto context = CreateContextWithTestCertificate(TLS_method());
    TLSSocket socket{context.get(), is_server};
    connect<port_ferret_rep>(socket);

    // Generate a random input.
    emp::block input;
    Util::generate_random_bytes<sizeof(input)>(&input);

    // Use Ferret.
    EmpWrapper<> wrapper{socket.get_ssl_object()};
    EmpWrapper<> *as_arr[2]{&wrapper, &wrapper};
    emp::FerretCOT<EmpWrapper<>> ot(((is_server) ? emp::ALICE : emp::BOB), 1,
                                    as_arr, true, true);

    BM_repeated(ot, socket.get_ssl_object(), state, input);
  }

  static void BM_repeated_IKNP(benchmark::State &state) {
    state.PauseTiming(); // Don't time the TLS session creation.
    auto context = CreateContextWithTestCertificate(TLS_method());

    TLSSocket socket{context.get(), is_server};
    connect<port_iknp_rep>(socket);
    // Generate a random input.
    emp::block input;
    Util::generate_random_bytes<sizeof(input)>(&input);

    // Use IKNP.
    EmpWrapper<> wrapper{socket.get_ssl_object()};
    emp::IKNP<EmpWrapper<>> ot(&wrapper, true);
    BM_repeated(ot, socket.get_ssl_object(), state, input);
  }
};

BENCHMARK(F2128_MTABench<IS_SERVER>::BM_batched_ferret)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(F2128_MTABench<IS_SERVER>::BM_batched_IKNP)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(F2128_MTABench<IS_SERVER>::BM_repeated_ferret)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(F2128_MTABench<IS_SERVER>::BM_repeated_IKNP)
    ->Unit(benchmark::kMillisecond);

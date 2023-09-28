#include "../mta/ectf.hpp"
#include "../ssl/TLSSocket.hpp"
#include "../ssl/TestUtil.hpp"
#include <benchmark/benchmark.h>
#include <thread>

// This benchmark tries to measure the cost of doing an EcTF computation
// over TLS. The actual instantiation is done via the struct below.
// This is to allow you to run this over a network.

template <bool is_server> struct ECTF_Bench {
  // Set your server IP here!
  inline static const std::string server_ip = "127.0.0.1";

  // Set your desired port here!
  inline static constexpr uint16_t portl = 18001;

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

private:
  inline static void ECTF(benchmark::State &state, TLSSocket &socket,
                          bssl::Array<uint8_t> &x_key_store,
                          bssl::Array<uint8_t> &y_key_store) {
    state.ResumeTiming();
    bssl::Array<uint8_t> secret;
    for (auto _ : state) {
      ECtF::ectf(secret, socket.get_ssl_object(), x_key_store, y_key_store,
                 SSL_CURVE_SECP256R1, is_server);
    }
  }

public:
  inline static void BM_ectf(benchmark::State &state) {
    state.PauseTiming();
    auto context = CreateContextWithTestCertificate(TLS_method());
    TLSSocket socket{context.get(), is_server};
    connect<portl>(socket);
    bssl::UniquePtr<BN_CTX> rbn_ctx(BN_CTX_new());
    assert(rbn_ctx);
    bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(
        Util::get_nid_from_uint16(SSL_CURVE_SECP256R1)));
    assert(group);
    bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
    Util::RandomECPoint(group.get(), point.get(), rbn_ctx.get());

    BIGNUM *x = BN_CTX_get(rbn_ctx.get());
    BIGNUM *y = BN_CTX_get(rbn_ctx.get());

    EC_POINT_get_affine_coordinates_GFp(group.get(), point.get(), x, y,
                                        rbn_ctx.get());
    const auto size = (EC_GROUP_get_degree(group.get()) + 7) / 8;
    bssl::Array<uint8_t> x_key_store, y_key_store;
    x_key_store.Init(size);
    y_key_store.Init(size);

    BN_bn2bin_padded(x_key_store.data(), x_key_store.size(), x);
    BN_bn2bin_padded(y_key_store.data(), y_key_store.size(), y);
    ECTF(state, socket, x_key_store, y_key_store);
  }
};

BENCHMARK(ECTF_Bench<IS_SERVER>::BM_ectf);

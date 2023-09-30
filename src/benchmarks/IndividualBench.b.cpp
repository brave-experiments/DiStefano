// This file exists to allow one to easily benchmark how long the various stages
// of the circuit execution takes in an individual context (i.e without worrying
// about the rest of the protocol). At a high-level, the program works as
// follows: 1) Each circuit type is encoded in a struct. You need to explicitly
// specify this structure to make sure that the
//    execution routine can be sufficiently high-level.
// 2) The exeuction routine repeats the circuit execution from end-to-end some
// number of times. 3) All execution is done over a single socket. We use the
// emp socket family for this if TCP is requested, and we use BoringSSL if ssl
// is requested.

#include "../mta/F2128MtA.hpp"
#include "../mta/MtA.hpp"
#include "../mta/ectf.hpp"
#include "../ssl/EmpWrapper.hpp"
#include "../ssl/EmpWrapperAG2PC.hpp"
#include "../ssl/TLSSocket.hpp"
#include "../ssl/TestUtil.hpp"
#include "../ssl/Util.hpp"
#include <array>
#include <cassert>
#include <chrono>
#include <climits>
#include <cstdint>
#include <getopt.h>
#include <iomanip>
#include <iostream>
#include <string>
// This struct just contains the information about the underlying circuit and
// not the socket type: thast needs to be specified later.
struct CircuitType {
  std::string name;
  const char *const filepath;
  const char *const text_output;
  unsigned input_bytes;
  unsigned output_bytes;

  CircuitType(const char *const name_, const char *const filepath_,
              const char *const text_output_, const unsigned ib,
              const unsigned ob)
      : name(name_), filepath(filepath_), text_output(text_output_),
        input_bytes(ib), output_bytes(ob) {}
};

using Tp = std::chrono::duration<double, std::milli>;

struct Timing {
  Tp setup;
  Tp indep_preproc;
  Tp dep_preproc;
  Tp exec;

  uint64_t setup_bytes;
  uint64_t indep_bytes;
  uint64_t dep_bytes;
  uint64_t run_bytes;
};

template <typename T, typename IT>
static Timing execute_impl(T &circuit_exec, IT &io, const unsigned input_bytes,
                           const unsigned output_bytes) noexcept {

  // These have to be malloced because of std::vector<bool> weirdness.
  bool *input = new bool[2 * CHAR_BIT * input_bytes]{};
  bool *output = new bool[CHAR_BIT * output_bytes]{};

  assert(input);
  assert(output);

  auto start_b = io.get_bandwidth();

  Timing time;
  auto start = std::chrono::steady_clock::now();
  circuit_exec.function_independent();
  time.indep_preproc = std::chrono::steady_clock::now() - start;
  time.indep_bytes = io.get_bandwidth() - start_b;
  start_b = io.get_bandwidth();

  start = std::chrono::steady_clock::now();
  circuit_exec.function_dependent();
  time.dep_preproc = std::chrono::steady_clock::now() - start;
  time.dep_bytes = io.get_bandwidth() - start_b;
  start_b = io.get_bandwidth();

  start = std::chrono::steady_clock::now();
  circuit_exec.online(input, output, true);
  time.exec = std::chrono::steady_clock::now() - start;
  time.run_bytes = io.get_bandwidth() - start_b;

  delete[] input;
  delete[] output;
  return time;
}

template <typename T, typename F>
static void execute_bench_ot(CircuitType &circ, T &io, const int mode,
                             const unsigned iterations, std::string &header,
                             std::string &body, const std::string &kind,
                             const std::string &ot_type, F &&build_func) {

  std::vector<Timing> timings(iterations);
  std::copy(circ.name.begin(), circ.name.end(), body.begin() + 2);
  auto iter = body.begin() + 2 + static_cast<int>(circ.name.size());
  while (iter < body.end() - 2) {
    *iter = ' ';
    ++iter;
  }

  const bool alice = mode == emp::ALICE;
  if (alice) {
    std::cout << header << body << header << kind << '\n';
  }

  std::flush(std::cout);
  emp::BristolFormat circuit_file(circ.filepath);

  for (unsigned i = 0; i < iterations; i++) {
    auto start_b = io.get_bandwidth();
    auto start = std::chrono::steady_clock::now();
    auto execl = build_func(circuit_file);
    auto setup = std::chrono::steady_clock::now() - start;
    auto used = io.get_bandwidth() - start_b;
    timings[i] = execute_impl(execl, io, circ.input_bytes, circ.output_bytes);
    timings[i].setup = setup;
    timings[i].setup_bytes = used;
  }

  if (alice) {
    // NOTE: the units of all timings are milliseconds,
    // and the units of all data output into the file are in bytes.
    std::ofstream file(std::string(circ.text_output) + "_" + ot_type + "_" +
                       std::to_string(iterations) + ".csv");
    file << "setup_time,indep_time,dep_time,online_time,setup_bytes,"
            "indep_bytes,dep_bytes,online_bytes"
         << '\n';

    auto setup_avg = timings[0].setup;
    auto indep_avg = timings[0].indep_preproc;
    auto dep_avg = timings[0].dep_preproc;
    auto onl_avg = timings[0].exec;

    auto setup_bytes_avg = timings[0].setup_bytes;
    auto indep_bytes_avg = timings[0].indep_bytes;
    auto dep_bytes_avg = timings[0].dep_bytes;
    auto run_bytes_avg = timings[0].run_bytes;

    for (unsigned i = 1; i < iterations; i++) {
      setup_avg += timings[i].setup;
      indep_avg += timings[i].indep_preproc;
      dep_avg += timings[i].dep_preproc;
      onl_avg += timings[i].exec;

      setup_bytes_avg += timings[i].setup_bytes;
      indep_bytes_avg += timings[i].indep_bytes;
      dep_bytes_avg += timings[i].dep_bytes;
      run_bytes_avg += timings[i].run_bytes;

      file << std::chrono::duration_cast<std::chrono::milliseconds>(
                  timings[i].setup)
                  .count()
           << ","
           << std::chrono::duration_cast<std::chrono::milliseconds>(
                  timings[i].indep_preproc)
                  .count()
           << ","
           << std::chrono::duration_cast<std::chrono::milliseconds>(
                  timings[i].dep_preproc)
                  .count()
           << ","
           << std::chrono::duration_cast<std::chrono::milliseconds>(
                  timings[i].exec)
                  .count()
           << "," << timings[i].setup_bytes << "," << timings[i].indep_bytes
           << "," << timings[i].dep_bytes << "," << timings[i].run_bytes
           << '\n';
    }

    std::cout << "setup_avg (ms):"
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     setup_avg / iterations)
                     .count()
              << '\n';
    std::cout << "indep_avg (ms):"
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     indep_avg / iterations)
                     .count()
              << '\n';
    std::cout << "dep_avg (ms):"
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     dep_avg / iterations)
                     .count()
              << '\n';
    std::cout << "onl_avg (ms):"
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     onl_avg / iterations)
                     .count()
              << '\n';
    std::cout << "setup_bytes_avg (mb): "
              << static_cast<double>(setup_bytes_avg) /
                     (iterations * (1024. * 1024.))
              << '\n';
    std::cout << "indep_bytes_avg (mb): "
              << static_cast<double>(indep_bytes_avg) /
                     (iterations * (1024. * 1024.))
              << '\n';
    std::cout << "dep_bytes_avg (mb): "
              << static_cast<double>(dep_bytes_avg) /
                     (iterations * (1024. * 1024.))
              << '\n';
    std::cout << "run_bytes_avg (mb): "
              << static_cast<double>(run_bytes_avg) /
                     (iterations * (1024. * 1024.))
              << '\n';

    std::cout << "total bandwidth_avg (mb):"
              << static_cast<double>(io.get_read_counter() +
                                     io.get_write_counter()) /
                     ((1024.0 * 1024.0) * iterations)
              << '\n';
    file.close();
    std::cout << std::endl;
  }
}

template <typename T>
static void execute_bench_ferret(CircuitType &circ, T &io, const int mode,
                                 const unsigned iterations, std::string &header,
                                 std::string &body, const int tag) {

  auto build_func = [&](emp::BristolFormat &circuit_file) {
    io.counter = 0;
    T *ios[]{&io, &io};
    return emp::C2PC<T, 1, FerretCOT>(ios, mode, tag, &circuit_file);
  };

  execute_bench_ot(circ, io, mode, iterations, header, body, "Kind: FerretCOT",
                   "ferret", build_func);
}

template <typename T>
static void execute_bench_leaky(CircuitType &circ, T &io, const int mode,
                                const unsigned iterations, std::string &header,
                                std::string &body, const int tag) {
  auto build_func = [&](emp::BristolFormat &circuit_file) {
    io.counter = 0;
    return emp::C2PC<T, 1, LeakyDeltaOT>(&io, mode, tag, &circuit_file);
  };

  execute_bench_ot(circ, io, mode, iterations, header, body,
                   "Kind: leaky delta OT", "leaky_delta_ot", build_func);
}

template <typename T>
static void execute_circuit_bench(T &io, const bool alice,
                                  const unsigned iterations) {
  CircuitType circuits[] = {
      CircuitType("TLS rotate key",
                  EmpWrapperAG2PCConstants::ROTATE_KEY_FILEPATH, "rotate_key",
                  EmpWrapperAG2PCConstants::ROTATE_KEY_IN_SIZE,
                  EmpWrapperAG2PCConstants::ROTATE_KEY_OUT_SIZE),
      CircuitType("AES GCM share naive",
                  EmpWrapperAG2PCConstants::GCM_NAIVE_FILEPATH, "gcm_naive",
                  EmpWrapperAG2PCConstants::GCM_IN_SIZE,
                  EmpWrapperAG2PCConstants::GCM_OUTPUT_SIZE),
      CircuitType("AES GCM shares Karatsuba",
                  EmpWrapperAG2PCConstants::GCM_FILEPATH, "gcm_karatsuba",
                  EmpWrapperAG2PCConstants::GCM_IN_SIZE,
                  EmpWrapperAG2PCConstants::GCM_OUTPUT_SIZE),
      CircuitType("AES128 Tag", EmpWrapperAG2PCConstants::AES_GCM_TAG_FILEPATH,
                  "gcm_tag", EmpWrapperAG2PCConstants::GCM_TAG_INPUT_SIZE,
                  EmpWrapperAG2PCConstants::GCM_TAG_OUTPUT_SIZE),
      CircuitType("AES128 Vfy", EmpWrapperAG2PCConstants::AES_GCM_VFY_FILEPATH,
                  "gcm_vfy", EmpWrapperAG2PCConstants::GCM_VFY_INPUT_SIZE,
                  EmpWrapperAG2PCConstants::GCM_VFY_OUTPUT_SIZE),
      CircuitType("TLS1.3 HS 256", EmpWrapperAG2PCConstants::CHS_256_FILEPATH,
                  "tls13_hs_256",
                  EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_256_IN_SIZE,
                  EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_OUTPUT_SIZE),
      CircuitType("TLS1.3 HS 384", EmpWrapperAG2PCConstants::CHS_384_FILEPATH,
                  "tls13_hs_384",
                  EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_384_IN_SIZE,
                  EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_OUTPUT_SIZE),
      CircuitType("TLS1.3 TS", EmpWrapperAG2PCConstants::TS_FILEPATH,
                  "tls13_ts", EmpWrapperAG2PCConstants::TRAFFIC_SECRETS_IN_SIZE,
                  EmpWrapperAG2PCConstants::TRAFFIC_SECRETS_OUTPUT_SIZE),

      CircuitType(
          "AES GCM Commit", EmpWrapperAG2PCConstants::AES_COMMIT_FILEPATH,
          "aes_gcm_commit", EmpWrapperAG2PCConstants::AES_COMMIT_IN_SIZE,
          EmpWrapperAG2PCConstants::AES_COMMIT_OUT_SIZE),
      CircuitType("2PC-GCM 256B",
                  EmpWrapperAG2PCConstants::AES_2PC_256_FILEPATH, "2pc-gcm-256",
                  EmpWrapperAG2PCConstants::AES_2PC_256_IN_SIZE,
                  EmpWrapperAG2PCConstants::AES_2PC_256_OUT_SIZE),
      CircuitType("2PC-GCM 512B",
                  EmpWrapperAG2PCConstants::AES_2PC_512_FILEPATH,
                  "2pc-gcm-1024", EmpWrapperAG2PCConstants::AES_2PC_512_IN_SIZE,
                  EmpWrapperAG2PCConstants::AES_2PC_512_OUT_SIZE),
      CircuitType("2PC-GCM 1KB", EmpWrapperAG2PCConstants::AES_2PC_1K_FILEPATH,
                  "2pc-gcm-1024", EmpWrapperAG2PCConstants::AES_2PC_1K_IN_SIZE,
                  EmpWrapperAG2PCConstants::AES_2PC_1K_OUT_SIZE),
      CircuitType("2PC-GCM 2KB", EmpWrapperAG2PCConstants::AES_2PC_2K_FILEPATH,
                  "2pc-gcm-2048", EmpWrapperAG2PCConstants::AES_2PC_2K_IN_SIZE,
                  EmpWrapperAG2PCConstants::AES_2PC_2K_OUT_SIZE),
  };

  const auto mode = (alice) ? emp::ALICE : emp::BOB;

  // Pretty printing stuff.
  const auto length =
      4 + std::max_element(std::cbegin(circuits), std::cend(circuits),
                           [](const CircuitType &a, const CircuitType &b) {
                             return a.name.length() < b.name.length();
                           })
              ->name.size();

  std::string header;
  header.reserve(length + 2);
  for (unsigned i = 0; i < length; i++) {
    header.push_back('*');
  }
  header += "\n";

  auto body = header;
  body[1] = ' ';
  *(body.rbegin() + 2) = ' ';

  int tag{};

  for (auto circ : circuits) {
    io.counter = 0;
    if (!Util::is_valid_filepath(circ.filepath)) {
      std::cerr << "Incorrect filepath for:" << circ.name << std::endl;
      std::abort();
    }

    body = header;
    body[1] = ' ';
    *(body.rbegin() + 2) = ' ';

    io.reset_bandwidth();
    execute_bench_leaky(circ, io, mode, iterations, header, body, tag);
    io.reset_bandwidth();
    execute_bench_ferret(circ, io, mode, iterations, header, body, tag + 1);
    tag += 2;
  }
}

template <typename T>
static void execute_mta_bench(T &io, const bool is_server,
                              const unsigned iterations) {
  // This function simply tries to evaluate the cost of doing MtA calls over a
  // variety of bit-sized inputs.
  // For consistency, we use the same 3 primes across each set of benchmarks.
  bssl::UniquePtr<EC_GROUP> p256(
      EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)),
      p384(EC_GROUP_new_by_curve_name(NID_secp384r1)),
      p521(EC_GROUP_new_by_curve_name(NID_secp521r1));
  assert(p256 && p384 && p521);

  // Get those primes too.
  auto p1 = EC_GROUP_get0_order(p256.get()),
       p2 = EC_GROUP_get0_order(p384.get()),
       p3 = EC_GROUP_get0_order(p521.get());

  // Now generate a random bignum to hold each.
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  assert(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());
  BIGNUM *a = BN_CTX_get(bn_ctx.get()), *b = BN_CTX_get(bn_ctx.get()),
         *c = BN_CTX_get(bn_ctx.get());
  assert(a && b && c);

  // Generate our random values.
  BN_rand_range_ex(a, 1, p1);
  BN_rand_range_ex(b, 1, p2);
  BN_rand_range_ex(c, 1, p3);

  // Now we'll actually do the timings. Note that here we
  // actually use a different BN_CTX in each loop iteration: this is to
  // try to be more accurate with regards to the timings (i.e we wouldn't re-use
  // a BN_CTX this many times in real code).

  // Just IKNP in these benchmarks too.
  emp::IKNP<T> ot(&io, true);

  auto iter = [&](const BIGNUM *in, const BIGNUM *prime,
                  const std::string &kind, const std::string &output_filepath) {
    Tp timing{};
    io.reset_bandwidth();

    std::ofstream *file{};
    if (is_server) {
      file = new std::ofstream(output_filepath + "_" +
                               std::to_string(iterations) + ".csv");
      (*file) << "time,bytes_exchanged" << '\n';
    }

    for (unsigned i = 0; i < iterations; i++) {
      bssl::UniquePtr<BN_CTX> lbn_ctx(BN_CTX_new());
      bssl::BN_CTXScope lscope(lbn_ctx.get());
      BIGNUM *out = BN_CTX_get(lbn_ctx.get());

      auto old_read = io.get_read_counter();
      auto old_write = io.get_write_counter();

      auto start = std::chrono::steady_clock::now();
      if (is_server) {
        MtA::play_sender(out, ot, in, prime, bn_ctx.get());
        auto time = std::chrono::steady_clock::now() - start;
        timing += time;
        (*file) << std::chrono::duration_cast<std::chrono::milliseconds>(time)
                       .count()
                << ","
                << (io.get_read_counter() + io.get_write_counter()) -
                       (old_read + old_write)
                << "\n";
      } else {
        MtA::play_receiver(out, ot, in, prime, bn_ctx.get());
      }
    }

    if (is_server) {
      std::cout << kind << " avg timing(ms):"
                << std::chrono::duration_cast<std::chrono::milliseconds>(
                       timing / iterations)
                       .count()
                << '\n'
                << "Bandwidth avg (mb):"
                << static_cast<double>(io.get_read_counter() +
                                       io.get_write_counter()) /
                       ((1024. * 1024.) * iterations)
                << '\n';
      std::cout << std::endl;
      file->close();
      delete file;
    }
  };

  iter(a, p1, "MtA P256", "mta_p256");
  iter(b, p2, "MtA P384", "mta_p384");
  iter(c, p3, "MtA P521", "mta_p521");
}

template <typename T>
static void execute_mta128_bench(T &io, SSL *under_io, const bool is_server,
                                 const unsigned iterations) {
  // This runs the batched MtA with either multiplicative shares or additive
  // shares. You need to change the "use_multiplicative_shares" in
  // F2128MtA.hpp to switch which is used.
  emp::IKNP<T> ot(&io, true);
  emp::block in;
  Util::generate_random_bytes<sizeof(in)>(&in);
  Tp timing{};
  Tp time{};
  uint64_t bandwidth{};

  if (is_server) {
    std::ofstream file("mta128_" + std::to_string(iterations) + ".csv");
    file << "time,bytes_exchanged" << '\n';
    for (unsigned i = 0; i < iterations; i++) {
      uint64_t tb{}, tbo{};
      auto start = std::chrono::steady_clock::now();
      F2128_MTA::generate_shares_verifier_batched(ot, *under_io, in, tb);
      time = std::chrono::steady_clock::now() - start;
      timing += time;

      io.recv_data(&tbo, sizeof(tbo));
      file
          << std::chrono::duration_cast<std::chrono::milliseconds>(time).count()
          << "," << tbo + tb << "\n";
      bandwidth += tbo + tb;
    }
    file.close();
  } else {
    for (unsigned i = 0; i < iterations; i++) {
      bandwidth = 0;
      F2128_MTA::generate_shares_prover_batched(ot, *under_io, in, bandwidth);
      io.send_data(&bandwidth, sizeof(bandwidth));
      io.flush();
    }
  }

  if (is_server) {
    std::cout << "F2128 MtA Batched timings (ms):"
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     timing / iterations)
                     .count()
              << '\n'
              << "Bandwidth avg (mb):"
              << static_cast<double>(bandwidth + io.get_read_counter() +
                                     io.get_write_counter()) /
                     ((1024. * 1024.) * iterations)
              << '\n';
    std::cout << std::endl;
  }
}

template <typename T>
static void execute_ectf_bench(T &io, SSL *under_io, const bool is_server,
                               const unsigned iterations) {

  // We just run this protocol using random bits of data. The
  // width of each `y`, `x` co-ordinate is changed depending on the underlying
  // prime: this is designed to make certain operations more difficult.
  bssl::UniquePtr<EC_GROUP> p256(
      EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)),
      p384(EC_GROUP_new_by_curve_name(NID_secp384r1)),
      p521(EC_GROUP_new_by_curve_name(NID_secp521r1));
  if (!p256 || !p384 || !p521) {
    std::cerr << "Invalid curve" << std::endl;
    std::abort();
  }
  assert(p256 && p384 && p521);

  // Now generate a random bignum to hold each.
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  assert(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());
  bssl::UniquePtr<EC_POINT> point_1(EC_POINT_new(p256.get()));
  bssl::UniquePtr<EC_POINT> point_2(EC_POINT_new(p384.get()));
  bssl::UniquePtr<EC_POINT> point_3(EC_POINT_new(p521.get()));

  Util::RandomECPoint(p256.get(), point_1.get(), bn_ctx.get());
  Util::RandomECPoint(p384.get(), point_2.get(), bn_ctx.get());
  Util::RandomECPoint(p521.get(), point_3.get(), bn_ctx.get());

  auto iter = [&](EC_GROUP *group, EC_POINT *point, const std::string &kind,
                  const uint16_t curve_id, const std::string &output_filepath) {
    bssl::Array<uint8_t> x, y;
    const auto size = (EC_GROUP_get_degree(group) + 7) / 8;
    x.Init(size);
    y.Init(size);

    BIGNUM *xp = BN_CTX_get(bn_ctx.get());
    BIGNUM *yp = BN_CTX_get(bn_ctx.get());
    EC_POINT_get_affine_coordinates_GFp(group, point, xp, yp, bn_ctx.get());
    BN_bn2bin_padded(x.data(), x.size(), xp);
    BN_bn2bin_padded(y.data(), y.size(), yp);

    Tp timing{};
    uint64_t bandwidth{};
    std::ofstream *file{};
    if (is_server) {
      file = new std::ofstream(output_filepath + "_" +
                               std::to_string(iterations) + ".csv");
      (*file) << "time,bytes_exchanged" << '\n';
    }

    bssl::Array<uint8_t> out;
    for (unsigned i = 0; i < iterations; i++) {
      auto start = std::chrono::steady_clock::now();
      uint64_t tb{};
      ECtF::ectf(out, under_io, x, y, curve_id, is_server, true, &tb);
      auto time = std::chrono::steady_clock::now() - start;
      if (is_server) {
        uint64_t tmp;
        io.recv_data(&tmp, sizeof(tmp));
        (*file) << std::chrono::duration_cast<std::chrono::milliseconds>(time)
                       .count()
                << "," << tmp + tb << "\n";
        bandwidth += tmp + tb;
        timing += time;
      } else {
        io.send_data(&tb, sizeof(tb));
        io.flush();
      }
    }

    if (is_server) {
      std::cout << kind << " avg timing(ms):"
                << std::chrono::duration_cast<std::chrono::milliseconds>(
                       timing / iterations)
                       .count()
                << '\n'
                << "Bandwidth avg (mb):"
                << static_cast<double>(bandwidth) /
                       ((1024. * 1024.) * iterations)
                << '\n';
      std::cout << std::endl;
      file->close();
      delete file;
    }
  };

  iter(p256.get(), point_1.get(), "ECtF P256", SSL_CURVE_SECP256R1,
       "ectf_p256");
  iter(p384.get(), point_2.get(), "ECtF P384", SSL_CURVE_SECP384R1,
       "ectf_p384");
  iter(p521.get(), point_3.get(), "ECtF P521", SSL_CURVE_SECP521R1,
       "ectf_p521");
}

int main(int argc, char **argv) {
  // Parse the arguments.
  bool is_server = false;
  std::string ip = "127.0.0.1";
  unsigned iterations = 50;

  const char *const short_opts = "sia:";
  const option long_opts[] = {{"is_server", no_argument, nullptr, 's'},
                              {"ip", required_argument, nullptr, 'a'},
                              {"iterations", required_argument, nullptr, 'i'}};

  for (;;) {
    const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
    if (opt == -1) {
      break;
    }

    switch (opt) {
    case 's':
      is_server = true;
      break;
    case 'a':
      ip = std::string(optarg);
      break;
    case 'i':
      iterations = static_cast<unsigned>(std::stoi(optarg));
      break;
    }
  }

  // Only use TLS.
  constexpr auto port = 32000;

  auto ctx = CreateContextWithTestCertificate(TLS_method());
  assert(ctx);
  TLSSocket socket(*ctx, is_server);
  if (!is_server) {
    socket.set_ip_v4();
    if (!socket.connect_to(ip, port)) {
      std::cerr << "Connecting to server failed" << std::endl;
      std::abort();
    }

    // Read the iterations count.
    socket.read(&iterations, sizeof(iterations));

  } else {
    const auto worked = socket.set_ip_v4() && socket.set_addr(ip) &&
                        socket.set_port(port) && socket.bind() &&
                        socket.listen(1);
    if (!worked) {
      std::cerr << "Binding failed on server" << std::endl;
      std::abort();
    }

    assert(worked);
    std::cerr << "Server: bind on ip:" << ip << std::endl;
    const auto connected = socket.accept() && socket.do_handshake();

    // Send over the iterations.
    socket.write(&iterations, sizeof(iterations));

    if (!connected) {
      std::cerr << "Accepting failed on server" << std::endl;
      std::abort();
    }
  }

  // Wrap into an emp socket.
  if (is_server) {
    std::cerr << "Starting benchmarks" << std::endl << std::endl;
  }

  // Set everything to 4SF, so that the results in the paper formatted the same
  // as here.
  std::cout << std::setprecision(4);

  using SSLBufferType = SSLBufferPolicy<SSL3_RT_MAX_PLAIN_LENGTH, true>;
  EmpWrapper<SSLBufferType, RWCounter> wrap(socket.get_ssl_object());
  execute_ectf_bench(wrap, socket.get_ssl_object(), is_server, iterations);
  execute_mta128_bench(wrap, socket.get_ssl_object(), is_server, iterations);
  execute_mta_bench(wrap, is_server, iterations);
  execute_circuit_bench(wrap, is_server, iterations);
}

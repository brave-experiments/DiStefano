/*
  This file exists to allow one to easily benchmark how long the 3P-HS takes in
  an end-to-end setting. At a high-level, this file similarly to the tests in
  Server.t.cpp: we simply run the 3P-HS forward between two parties.
*/

#include <getopt.h>

#include "../nodes/Server.hpp"
#include "../ssl/Messaging.hpp"
#include "../ssl/TestUtil.hpp"
#include <cstdint>
#include <iostream>
#include <string>
#include <thread>

template <bool debug = false> static bool read_handshake(TLSSocket &sock) {
  bssl::Array<uint8_t> arr;
  arr.Init(1);
  if (sock.read(arr.data(), static_cast<int>(arr.size())) != 1) {
    return false;
  }

  CBS cbs;
  CBS_init(&cbs, arr.data(), arr.size());
  uint8_t out;
  return CBS_get_u8(&cbs, &out) &&
         (out == static_cast<uint8_t>(Messaging::MessageHeaders::DONE_HS));
}

static bool set_callbacks(TLSSocket &socket) {
  socket.set_make_circuits();
  return socket.set_handshake_callback() && socket.set_keyshare_callback() &&
         socket.set_derive_shared_secret_callback() &&
         socket.set_derive_handshake_keys_callback() &&
         socket.set_commit_to_server_certificate_callback() &&
         socket.set_write_h6_callback() &&
         socket.set_derive_traffic_keys_callback() &&
         socket.set_derive_gcm_shares_callback();
}

static void server_hs(std::promise<bool> &&res, Server *server) {
  if (!server || !server->accept()) {
    res.set_value(false);
    return;
  }

  if (!server->do_handshake()) {
    res.set_value(false);
    return;
  }

  if (!server->write_handshake_done()) {
    res.set_value(false);
    return;
  }

  res.set_value(true);
  return;
}

static bool server_run(Server &server, Server &verifier) {
  // We just run the server in its own thread and the verifier on this thread.
  std::promise<bool> server_promise;
  auto s_fut = server_promise.get_future();
  std::thread server_thread(server_hs, std::move(server_promise), &server);
  std::cerr << "[Server] Running benchmark" << std::endl;
  auto worked = verifier.run(Server::ServerState::DONE, true, true);
  server_thread.join();
  return worked;
}

int main(int argc, char *argv[]) {
  // Parse the arguments.
  bool is_server = false;
  std::string ip = "127.0.0.1";

  uint16_t server_port{}, verifier_port{};

  const char *const short_opts = "sa:p:v:";
  const option long_opts[] = {
      {"is_server", no_argument, nullptr, 's'},
      {"ip", required_argument, nullptr, 'a'},
      {"server port", required_argument, nullptr, 'p'},
      {"verifier port", required_argument, nullptr, 'v'}};

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
    case 'p':
      server_port = static_cast<uint16_t>(std::stoi(optarg));
      break;
    case 'v':
      verifier_port = static_cast<uint16_t>(std::stoi(optarg));
      break;
    }
  }

  if (is_server) {
    Server verifier(CreateContextWithTestCertificate(TLS_method()), ip.c_str(),
                    false, 1);
    Server server(CreateContextWithTestCertificate(TLS_method()), ip.c_str(),
                  false, 1);

    verifier.get_portnumber(&verifier_port);
    server.get_portnumber(&server_port);
    std::cerr << "[Server] connect to server on:" << ip << ":" << server_port
              << " verifier on:" << ip << ":" << verifier_port << std::endl;

    std::cerr << "[Server] Alternatively, you can run the client program by "
                 "pasting the following command into another terminal: \n"
              << "./E2EBench --ip " << ip << " -p " << server_port << " -v "
              << verifier_port << std::endl;

    server_run(server, verifier);
  } else {
    struct Prover {
      TLSSocket connection_to_verifier;
      TLSSocket connection_to_server;
    };

    auto pv_ctx = CreateContextWithTestCertificate(TLS_method());
    auto ps_ctx = CreateContextWithTestCertificate(TLS_method());

    Prover prover{TLSSocket(pv_ctx.get(), false),
                  TLSSocket(ps_ctx.get(), false)};
    prover.connection_to_server.set_ip_v4();
    prover.connection_to_verifier.set_ip_v4();

    if (!prover.connection_to_verifier.connect_to(ip, verifier_port) ||
        !read_handshake(prover.connection_to_verifier)) {
      std::cerr << "[Prover] connecting to verifier on:" << ip << ":"
                << verifier_port << "failed!" << std::endl;
      std::abort();
    }

    // Set all the stuff up.
    if (!prover.connection_to_server.set_verifier_connection(
            prover.connection_to_verifier.get_ssl_object())) {
      std::cerr << "[Prover] Setting verifier failed" << std::endl;
      std::abort();
    }

    if (!set_callbacks(prover.connection_to_server)) {
      std::cerr << "[Prover] Setting callbacks failed" << std::endl;
      std::abort();
    }

    // Just run the connection.
    prover.connection_to_server.connect_to(ip, server_port);
  }
}

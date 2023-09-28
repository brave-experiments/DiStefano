#include "Server.hpp"
#include "../Decl.hpp"
#include "../ssl/Messaging.hpp"
#include "openssl/base.h" // This only contains the forward declarations for SSL* etc.
#include "ssl/internal.h" // This contains the declaration for Array.
#include <array>
#include <iostream>

#define CONCAT_IMPL(x, y) x##y
#define MACRO_CONCAT(x, y) CONCAT_IMPL(x, y)
#define TIME(event)                                                            \
  Timer::TimeIt<Timer::TimerType> MACRO_CONCAT(timer, __COUNTER__)(timer, event)
#define TRACK_IF_INTERESTED(event, amount)                                     \
  do {                                                                         \
    if constexpr (BandwidthTracker::TrackerType::is_interested(event)) {       \
      *bandwidth_tracker.get_memory_for(event) += amount;                      \
    }                                                                          \
  } while (0)

#define PRINT_IF_LOUD(x)                                                       \
  do {                                                                         \
    if (this->loud) {                                                          \
      std::cerr << "[Server] " << x << std::endl;                              \
    }                                                                          \
  } while (0)

SSL *Server::get_ssl() { return socket.get_ssl_object(); }

void Server::set_cipher_suite(const uint16_t cipher_suite_in) noexcept {
  this->cipher_suite = cipher_suite_in;
}

void Server::set_version(const uint16_t version_in) noexcept {
  this->version = version_in;
}

KeyShare &Server::get_active_share() { return key_shares[active_key_share]; }

Server::Server(bssl::UniquePtr<SSL_CTX> &&ctx, const std::string &ip_address,
               const bool is_ip_v6, const int backlog) noexcept
    : ssl_ctx{std::move(ctx)}, key_shares{}, public_key{},
      additive_share{}, state{ServerState::ACCEPT}, ret_code{},
      socket(*ssl_ctx), buffer{}, x_secret{}, transcript{}, transcript_obj{},
      handshake_key_shares{}, version{}, cipher_suite{}, timer{},
      bandwidth_tracker{} {
  // Not really much we can do here in case of failure.
  [[maybe_unused]] const bool initialised_correctly =
      socket.is_ssl_valid() && buffer.Init(SSL3_RT_MAX_PLAIN_LENGTH);

  assert_and_assume(initialised_correctly);

  // This is called an immediately-invoked lambda expression.
  // See the README for more.
  [[maybe_unused]] const bool setup = [&]() {
    if (is_ip_v6) {
      return socket.set_ip_v6() && socket.set_addr(ip_address) &&
             socket.bind() && socket.listen(backlog);
    }

    return socket.set_ip_v4() && socket.set_addr(ip_address) && socket.bind() &&
           socket.listen(backlog);
  }();

  assert_and_assume(setup);
}

std::array<uint16_t, 2> Server::get_curve_ids() const noexcept {
  return {key_shares[0].get_group_id(), key_shares[1].get_group_id()};
}

bool Server::get_additive_share(bssl::Array<uint8_t> &arr) const noexcept {
  bssl::Array<uint8_t> share_1, share_2;
  if (!key_shares[0].get_additive_share(share_1) ||
      !key_shares[1].get_additive_share(share_2)) {
    PRINT_IF_LOUD("Failed to get additive shares");
    return false;
  }

  if (!arr.Init(share_1.size() + share_2.size())) {
    PRINT_IF_LOUD("Failed to init shares in get_additive_shares");
    return false;
  }

  if (!share_1.empty()) {
    std::copy(share_1.begin(), share_1.end(), arr.begin());
  }

  if (!share_2.empty()) {
    const auto offset = share_1.size();
    std::copy(share_2.begin(), share_2.end(), arr.begin() + offset);
  }
  return true;
}

bool Server::get_public_key(bssl::Array<uint8_t> &arr) const noexcept {

  bssl::Array<uint8_t> share_1, share_2;
  if (!key_shares[0].get_public_key(share_1) ||
      !key_shares[1].get_public_key(share_2)) {
    PRINT_IF_LOUD("Failed to get public keys in get_public_key");
    return false;
  }

  if (!arr.Init(share_1.size() + share_2.size())) {
    PRINT_IF_LOUD("Failed to init array in get_public_key");
    return false;
  }

  if (!share_1.empty()) {
    std::copy(share_1.begin(), share_1.end(), arr.begin());
  }

  if (!share_2.empty()) {
    const auto offset = share_1.size();
    std::copy(share_2.begin(), share_2.end(), arr.begin() + offset);
  }

  return true;
}

static constexpr Server::ServerState
next_state(const Server::ServerState state) {
  // This function returns the "next" server state from a given `state`.
  // You can view this function as a transition graph: it tells you where the
  // server is going.

  // To make this as neat as possible, we'll exploit certain properties of the
  // ServerState enum. It's an ordered enum: each state follows from the next
  // one.
  // This is equivalent to incrementing each state, with DONE being the maximum.
  // We can handle this.
  // Should check first that the sizes match up.
  static_assert(sizeof(Server::ServerState) == sizeof(uint8_t),
                "Error: ServerState is no longer the sizeof a uint8_t");

  switch (state) {
  case Server::ServerState::DONE:
    return state;
  case Server::ServerState::READING_SKS:
    return Server::ServerState::FINISHING_TPH;
  default:
    return static_cast<Server::ServerState>((static_cast<uint8_t>(state) + 1));
  }
}

static bool read_keyshare(Messaging::MessageHeaders &header, TLSSocket &socket,
                          bssl::Array<uint8_t> &buffer,
                          bssl::Array<uint8_t> &out) {
  const auto nr_bytes =
      socket.read(buffer.data(), static_cast<int>(buffer.size()));
  if (nr_bytes <= 0) {
    return false;
  }

  // The only check we do here is that the header is valid: the callers know
  // better with regards to what they want to do with the output data.
  return Messaging::unpack_key_bytes(
      header, bssl::MakeSpan(buffer.data(), static_cast<size_t>(nr_bytes)),
      out);
}

bool Server::read_sks_keyshare() noexcept {
  // Note: we don't actually need to check the state here, otherwise
  // we wouldn't have entered this function.
  // But we do it anyway: in release builds this will turn off.
  assert(this->state == ServerState::READING_SKS);
  TIME(Events::State::READING_SKS);

  // Now we'll just delegate to the actual routine.
  // We also want the key share to be a server key share (ideally)
  Messaging::MessageHeaders header;
  if (!read_keyshare(header, socket, buffer, client_public_key) ||
      header != Messaging::MessageHeaders::SERVER_KEY_SHARE) {
    PRINT_IF_LOUD("Failed to read sks_key_share header");
    return false;
  }

  // The + here is to account for us reading the header too.
  TRACK_IF_INTERESTED(Events::State::READING_SKS,
                      client_public_key.size() +
                          sizeof(Messaging::MessageHeaders));

  // NOTE: we'll do the actual parsing when it comes to creating the key share.
  // Update the state
  this->state = next_state(this->state);
  return true;
}

bool Server::read_keyshare_after_handshake() noexcept {
  // NOTE: we don't check the state here. This is because in normal
  // operation we have the guard in the `run` function to check this,
  // and also because it interferes with testing a bit.
  // Now we'll just delegate to the actual routine.
  TIME(Events::State::READING_KS);
  Messaging::MessageHeaders header;
  if (!read_keyshare(header, socket, buffer, client_public_key) ||
      header != Messaging::MessageHeaders::COLLECT) {
    PRINT_IF_LOUD("Failed to read key share after handshake");
    return false;
  }

  // The + here is to account for us reading the header too.
  TRACK_IF_INTERESTED(Events::State::READING_KS,
                      client_public_key.size() +
                          sizeof(Messaging::MessageHeaders));

  // Again, we'll look into parsing this in the next step.
  // Update the state
  this->state = next_state(ServerState::READING_KS);
  return true;
}

bool Server::get_portnumber(uint16_t *const out) const noexcept {
  return socket.get_portnumber(out);
}

bool Server::accept() noexcept {
  TIME(Events::State::ACCEPT);
  if (socket.accept()) {
    this->state = next_state(this->state);
    return true;
  }
  return false;
}

bool Server::do_handshake() noexcept {
  // Note: if there's a message on the socket, then we need to read that
  // message, and ultimately dispatch to another function. The reason for this
  // is because the SSL_read function does the handshake implicitly if there
  // are any pending. In addition, because we share a single BIO across both
  // reading and writing, writing out the handshake done would overwrite the
  // sent data. Otherwise we'll just do the normal handshake. 1 is the success
  // condition
  TIME(Events::State::HANDSHAKE);

  if (socket.do_handshake() != 1) {
    PRINT_IF_LOUD("Failed to do handshake");
    return false;
  }

  // If there's nothing here to read, then we'll go to writing
  // the handshake out.
  if (socket.pending() == 0) {
    this->state = ServerState::HANDSHAKE_DONE;
    return true;
  }

  // We're actually now reading the key share.
  this->state = ServerState::READING_KS;

  // Read the data that's waiting for us.
  const auto read = socket.read(buffer.data(), static_cast<int>(buffer.size()));
  if (read <= 0) {
    // We failed
    PRINT_IF_LOUD("Failed to read extra data in handshake");
    return false;
  }

  // the + here is because of the write that we're about to do (see below).
  TRACK_IF_INTERESTED(Events::State::HANDSHAKE,
                      static_cast<uint64_t>(read) +
                          sizeof(Messaging::MessageHeaders));

  // Otherwise, we might have a message we need. We'll write that the
  // handshake succeeded, then we'll parse it.
  Messaging::MessageHeaders header;
  if (!write_handshake_done() ||
      !Messaging::unpack_key_bytes(header, buffer, client_public_key) ||
      header != Messaging::MessageHeaders::COLLECT) {
    PRINT_IF_LOUD("Failed to write handshake done or unpack key bytes");
    return false;
  }

  this->state = ServerState::MAKING_KS;
  return true;
}

bool Server::create_new_share() noexcept {
  TIME(Events::State::MAKING_KS);
  return create_new_share(this->client_public_key);
}

bool Server::do_preproc(const bool should_preproc) noexcept {
  TIME(Events::State::CIRCUIT_PREPROC);
  if (!should_preproc) {
    this->state = next_state(this->state);
    return true;
  }

  // Initialise the circuits. Warning: the layout here has to be like this. This
  // is because the call to the constructor for the underlying object may
  // exchange data over "ssl", which can confuse emp.
  handshake_circuits[0].reset(EmpWrapperAG2PC::build_derive_hs_circuit(
      socket.get_ssl_object(), key_shares[0].get_group_id(), emp::BOB,
      EmpWrapperAG2PCConstants::HANDSHAKE_CIRCUIT_TAG_A));
  if (handshake_circuits[0]) {
    PRINT_IF_LOUD("Preproc HS1 circuit");
    handshake_circuits[0]->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        handshake_circuits[0]->get_counter());
  }

  handshake_circuits[1].reset(EmpWrapperAG2PC::build_derive_hs_circuit(
      socket.get_ssl_object(), key_shares[1].get_group_id(), emp::BOB,
      EmpWrapperAG2PCConstants::HANDSHAKE_CIRCUIT_TAG_B));

  if (handshake_circuits[1]) {
    PRINT_IF_LOUD("Preproc HS2 circuit");
    handshake_circuits[1]->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        handshake_circuits[1]->get_counter());
  }

  traffic_circuit.reset(EmpWrapperAG2PC::build_derive_ts_circuit(
      socket.get_ssl_object(), emp::BOB,
      EmpWrapperAG2PCConstants::TRAFFIC_CIRCUIT_TAG));
  if (traffic_circuit) {
    PRINT_IF_LOUD("Preproc traffic circuit");
    traffic_circuit->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        traffic_circuit->get_counter());
  }

  aes_joint_circuit.reset(EmpWrapperAG2PC::build_joint_aes_circuit(
      socket.get_ssl_object(), emp::BOB,
      EmpWrapperAG2PCConstants::AES_JOINT_CIRCUIT_TAG));
  if (aes_joint_circuit) {
    PRINT_IF_LOUD("Preproc aes joint circuit");
    aes_joint_circuit->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        aes_joint_circuit->get_counter());
  }

  gcm_circuit.reset(EmpWrapperAG2PC::build_gcm_circuit(
      socket.get_ssl_object(), emp::BOB,
      EmpWrapperAG2PCConstants::GCM_CIRCUIT_TAG));
  if (gcm_circuit) {
    PRINT_IF_LOUD("Preproc gcm share circuit");
    gcm_circuit->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        gcm_circuit->get_counter());
  }
  this->state = next_state(this->state);
  return true;
}

bool Server::create_new_share(
    const bssl::Array<uint8_t> &other_key_bytes) noexcept {
  // See Util.hpp for this
  static_assert(
      Util::only_nist_curves,
      "Error: code now supports Curve25519: have you updated this function?");

  // The input key bytes array can be one of two things here.
  // 1. It can be an array that contains a single public key.
  // If this is the case, then the array will have a 16-bit group ID,
  // a 16-bit length, and then a key.
  // 2. It can be an array that contains two public keys.
  // In this case the format is the same as before, but there'll be
  // some extra length left over when we load the key.
  CBS cbs, key;
  CBS_init(&cbs, other_key_bytes.data(), other_key_bytes.size());

  // It turns out we can implicitly convert between CBS' and Spans, so this call
  // can be direct.
  uint16_t group_id[2];
  if (!CBS_get_u16(&cbs, &group_id[0]) ||
      !CBS_get_u16_length_prefixed(&cbs, &key) ||
      !key_shares[0].create_new_share(group_id[0], key)) {
    PRINT_IF_LOUD("Failed to create first key share");
    return false;
  }

  // If there's not another key left then we're done.
  if (CBS_len(&cbs) == 0) {
    this->state = next_state(this->state);
    return true;
  }

  // Otherwise, make the other share.
  // Here we're a bit more lucky; we just need to
  // convert the CBS back into an array.
  bssl::Array<uint8_t> key_2_bytes;
  if (!CBS_get_u16(&cbs, &group_id[1]) ||
      !CBS_get_u16_length_prefixed(&cbs, &key) ||
      !key_shares[1].create_new_share(group_id[1], key)) {
    PRINT_IF_LOUD("Failed to create second key share");
    return false;
  }

  if (CBS_len(&cbs) != 0) {
    PRINT_IF_LOUD("Received extra data in create_new_share");
    return false;
  }

  this->state = next_state(this->state);
  return true;
}

bool Server::send_additive_share() {
  TIME(Events::State::WRITING_KS);
  if (!get_additive_share(additive_share)) {
    PRINT_IF_LOUD("Failed to get additive share in send_additive_share");
    return false;
  }

  bssl::Array<uint8_t> bytes;
  if (!Messaging::pack_key_bytes(Messaging::MessageHeaders::OK, additive_share,
                                 bytes)) {
    PRINT_IF_LOUD("Failed to pack key bytes in send_additive_share");
    return false;
  }

  TRACK_IF_INTERESTED(Events::State::WRITING_KS, bytes.size());

  if (socket.write(bytes.data(), bytes.size(), &ret_code)) {
    this->state = next_state(this->state);
    return true;
  }
  PRINT_IF_LOUD("Failed to send bytes in send_additive_share");
  return false;
}

template <typename T, typename F>
static bool read_single_integral(TLSSocket &socket, T &out, F &&func) noexcept {
  // Note; this would be an obvious optimisation point, as sending small
  // messages is expensive. The system call costs the same regardless of the
  // number of bytes you send.
  static_assert(std::is_integral_v<T> || std::is_same_v<std::byte, T>,
                "Error: cannot instantiate read_single_integral with "
                "non-integral or byte T");

  T buf;
  CBS in_cbs;

  const auto amount_read = socket.read(&buf, sizeof(T));
  if (amount_read <= 0 || static_cast<unsigned>(amount_read) != sizeof(T)) {
    return false;
  }

  // This cast is legal because uint8_t can alias any other type.
  CBS_init(&in_cbs, reinterpret_cast<const uint8_t *>(&buf), sizeof(buf));
  return func(in_cbs, out);
}

static bool read_single_u64(TLSSocket &socket, uint64_t &size) noexcept {
  auto func = [](CBS &cbs, uint64_t &arg) { return CBS_get_u64(&cbs, &arg); };

  return read_single_integral(socket, size, func);
}

static bool read_single_u16(TLSSocket &socket, uint16_t &val) noexcept {
  auto func = [](CBS &cbs, uint16_t &arg) { return CBS_get_u16(&cbs, &arg); };
  return read_single_integral(socket, val, func);
}

static bool read_single_header(TLSSocket &socket,
                               Messaging::MessageHeaders &header) {
  // This static check here is to make sure that the
  // size of the enum hasn't changed without us noticing (this sort of silent
  // break is insidious).
  static_assert(
      sizeof(Messaging::MessageHeaders) == sizeof(uint8_t),
      "Error: sizeof(Messaging::MessageHeaders is no longer sizeof(uint8_t)");

  // Note: this variable is initialised when it's used below. If you default
  // initialise this then you'll miss a useful GCC warning if you happen to get
  // the type of the lambda wrong (which this author did initially...)
  uint8_t in_header;
  auto func = [](CBS &cbs, uint8_t &arg) {
    return CBS_get_u8(&cbs, &arg) && Messaging::is_valid_header(arg);
  };
  if (!read_single_integral(socket, in_header, func)) {
    return false;
  }

  header = static_cast<Messaging::MessageHeaders>(in_header);
  return true;
}

static bool write_single_header(TLSSocket &socket,
                                const Messaging::MessageHeaders header) {
  // Note; this would be an obvious optimisation point, as sending small
  // messages is expensive. The system call costs the same regardless of the
  // number of bytes you send.
  // This is also expensive because we heap allocate etc.
  bssl::ScopedCBB cbb;
  bssl::Array<uint8_t> arr;

  // This static check here is to make sure that the
  // size of the enum hasn't changed without us noticing (this sort of silent
  // break is insidious).
  static_assert(
      sizeof(Messaging::MessageHeaders) == sizeof(uint8_t),
      "Error: sizeof(Messaging::MessageHeaders is no longer sizeof(uint8_t)");

  if (!CBB_init(cbb.get(), 1) ||
      !CBB_add_u8(cbb.get(), static_cast<uint8_t>(header)) ||
      !CBBFinishArray(cbb.get(), &arr) ||
      !socket.write(arr.data(), sizeof(uint8_t))) {
    return false;
  }

  return true;
}

static bool handshake_done_impl(TLSSocket &socket) {
  if (socket.pending() != 0) {
    std::cerr << "Error: attempted to write handshake done, but another "
                 "message was waiting.\n"
              << "This will likely cause data loss." << std::endl;
  }
  return write_single_header(socket, Messaging::MessageHeaders::DONE_HS);
}

bool Server::do_ectf() noexcept {
  // We'll read a single header. If the header isn't what we wanted (e.g a
  // Messaging::MessageHeaders::DO_ECTF) then we bail. Otherwise, we'll do the
  // ECTF.
  TIME(Events::State::ECTF_WAIT);
  Messaging::MessageHeaders header = Messaging::MessageHeaders::SIZE;
  TRACK_IF_INTERESTED(Events::State::ECTF_WAIT,
                      sizeof(Messaging::MessageHeaders));
  if (!read_single_header(socket, header) ||
      header != Messaging::MessageHeaders::DO_ECTF) {
    PRINT_IF_LOUD("Failed to read ectf header");
    return false;
  }

  // If not, then call into the ECTF functionality directly.
  auto &key_share = key_shares[active_key_share];
  const auto worked =
      ECtF::ectf(x_secret, socket.get_ssl_object(), key_share.get_x_secret(),
                 key_share.get_y_secret(), key_share.get_group_id(), true,
                 bandwidth_tracker.is_interested(Events::State::ECTF_WAIT),
                 bandwidth_tracker.get_memory_for(Events::State::ECTF_WAIT));
  if (!worked) {
    PRINT_IF_LOUD("Failed to complete ectf");
    return false;
  }

  // Update the state machine.
  this->state = next_state(this->state);
  return true;
}

bool Server::finish_ectf() noexcept {
  TIME(Events::State::ECTF_DONE);
  TRACK_IF_INTERESTED(Events::State::ECTF_DONE,
                      sizeof(Messaging::MessageHeaders::ECTF_DONE));
  // We'll just write a single header.
  if (!write_single_header(socket, Messaging::MessageHeaders::ECTF_DONE)) {
    PRINT_IF_LOUD("Failed to write ectf finished header");
    return false;
  }

  // We're done with the ECTF!
  this->state = next_state(this->state);
  return true;
}

bool Server::write_handshake_done() noexcept {
  TIME(Events::State::HANDSHAKE_DONE);
  // Again, we need to peek here to make sure we haven't received anything in.
  if (socket.pending() != 0) {
    // Read the data that's waiting for us.
    const auto read =
        socket.read(buffer.data(), static_cast<int>(buffer.size()));
    if (read <= 0) {
      PRINT_IF_LOUD("Failed to read extra data in write_handshake_done");
      // We failed
      return false;
    }

    TRACK_IF_INTERESTED(Events::State::HANDSHAKE_DONE,
                        static_cast<uint64_t>(read));

    // If we've read a message here, then it's a keyshare.
    // We'll write out the handshake and then do the parsing.
    // WARNING: if another message has been sent in the meantime this
    // will log an error.
    Messaging::MessageHeaders header;
    if (!handshake_done_impl(socket) ||
        !Messaging::unpack_key_bytes(header, buffer, client_public_key) ||
        header != Messaging::MessageHeaders::COLLECT) {
      PRINT_IF_LOUD("Failed to unpack extra key bytes in write_handshake_done");
      return false;
    }

    // We'll need to update the state here
    this->state = ServerState::MAKING_KS;
    return true;
  }

  if (!handshake_done_impl(socket)) {
    PRINT_IF_LOUD("Failed to execute handshake_done in write_handshake_done");
    return false;
  }

  this->state = ServerState::READING_KS;
  return true;
}

bool Server::finish_tph() noexcept {
  // See Util.hpp for this
  static_assert(
      Util::only_nist_curves,
      "Error: code now supports Curve25519: have you updated this function?");

  TIME(Events::State::FINISHING_TPH);
  // In this situation we have a key share (in client_public_key)
  // and a key share of our own in share. As a result, all we really need
  // to do is finish off the EC multiplication.

  // The first thing to check is that the read key has a
  // key share that matches one of ours.

  CBS cbs, key;
  CBS_init(&cbs, client_public_key.data(), client_public_key.size());
  if (client_public_key.size() == 0) {
    PRINT_IF_LOUD("Empty client public key in finish_tph");
    return false;
  }

  // Extract the group's ID and make sure the buffer is well-formed.
  uint16_t group_id;
  if (!CBS_get_u16(&cbs, &group_id) ||
      !CBS_get_u16_length_prefixed(&cbs, &key) || CBS_len(&cbs) != 0) {
    PRINT_IF_LOUD("Failed to extract group ID from buffer in finish_tph");
    return false;
  }

  // Now we'll extract the key share that matches ours.
  const auto active_element = std::find_if(
      std::cbegin(key_shares), std::cend(key_shares),
      [&](const KeyShare &share) { return share.get_group_id() == group_id; });

  // If the key share doesn't match, then we have to bail.
  if (active_element == std::cend(key_shares)) {
    PRINT_IF_LOUD("No matching key share in finish_tph");
    return false;
  }

  // Now we'll turn that iterator into something useful.
  // Note; this cast is fine. In fact, because active_key_share is always at
  // most key_shares.size() - 1, we can tell the compiler that.
  active_key_share = static_cast<unsigned>(
      std::distance(std::cbegin(key_shares), active_element));

  // Now we'll actually "do the work".
  if (key_shares[active_key_share].finish(key)) {
    this->state = ServerState::WRITING_HS_RECV;
    return true;
  }

  PRINT_IF_LOUD("Failed to finish key share in finish_tph");
  return false;
}

bool Server::write_hs_recv() noexcept {
  TIME(Events::State::WRITING_HS_RECV);
  TRACK_IF_INTERESTED(Events::State::WRITING_HS_RECV,
                      sizeof(Messaging::MessageHeaders));
  if (socket.pending() != 0) {
    // This means there's data waiting for us.
    // Right now we have to abort here, in lieu of better
    // error checking.
    PRINT_IF_LOUD("Waiting data on write_hs_recv: aborting");
    std::abort();
  }

  // Now we'll just write a single header.
  if (!write_single_header(socket, Messaging::MessageHeaders::HS_RECV)) {
    PRINT_IF_LOUD("Failed to write HS_RECV in write_hs_recv");
    return false;
  }

  // Move to the next one.
  this->state = next_state(this->state);
  return true;
}

static constexpr bool should_stop(const Server::ServerState current,
                                  const Server::ServerState stop) {
  static_assert(sizeof(Server::ServerState) == sizeof(uint8_t),
                "Error: Server::ServerState is no longer sizeof(uint8_t)");

  return static_cast<uint8_t>(current) >= static_cast<uint8_t>(stop);
}

static bool read_transcript_data(TLSSocket &socket,
                                 bssl::Array<uint8_t> &buffer,
                                 std::vector<uint8_t> &transcript,
                                 const Messaging::MessageHeaders target_header,
                                 Server &server) noexcept {
  // First of all we need to read whatever header we have. We can also read the
  // size too.
  Messaging::MessageHeaders header;
  uint64_t size;
  if (!read_single_header(socket, header) || header != target_header) {
    return false;
  }

  // If we're in the initial portion we also have two
  // extra 16 bit values to read, corresponding to the SSL version
  // and the cipher suite used. Read those in too, since they're used
  // for the hash.
  if (target_header == Messaging::MessageHeaders::TRANSCRIPT_INIT) {
    uint16_t version, cipher_suite;
    if (!read_single_u16(socket, version) ||
        !read_single_u16(socket, cipher_suite)) {
      return false;
    }
    server.set_version(version);
    server.set_cipher_suite(cipher_suite);
  }

  // Now we can read the size.
  if (!read_single_u64(socket, size)) {
    return false;
  }

  if (target_header == Messaging::MessageHeaders::CERTIFICATE_CTX_RECV) {
    // There should be `size` many bytes that are committed to and an additional
    // 32 bytes for the key if we're in the Certificate RECV stage.
    constexpr auto hash_size = 32;
    if (socket.pending() != static_cast<int>(size + hash_size)) {
      return false;
    }
    // Make sure we read those extra bytes in too.
    size += hash_size;
  }

  // Reserve the size up.
  transcript.reserve(transcript.size() + size);

  do {
    const auto read =
        socket.read(buffer.data(), static_cast<int>(buffer.size()));
    if (read <= 0) {
      // We failed to read.
      return false;
    }

    // The buffer is already at the right size, so this will not cause
    // allocations.
    transcript.insert(transcript.end(), buffer.begin(), buffer.begin() + read);
  } while (socket.pending() != 0);

  return true;
}

bool Server::do_cert_wait() noexcept {
  TIME(Events::State::CERT_WAIT);
  // Here we just read the transcript message from the other party and
  // then reveal our secrets to them.
  if (!read_transcript_data(socket, buffer, transcript,
                            Messaging::MessageHeaders::CERTIFICATE_CTX_SEND,
                            *this)) {
    PRINT_IF_LOUD("Failed to read data in do_cert_wait");
    return false;
  }

  constexpr auto hash_size = 32;
  static_assert(sizeof(server_key_comm) == sizeof(uint8_t) * hash_size,
                "Error: mismatched hash size!");
  // The last hash_size bytes should be a commitment to the key, so we extract
  // those separately. N.B This check should be impossible if the other party is
  // playing honestly.
  if (transcript.size() < hash_size) {
    PRINT_IF_LOUD("Transcript size too small in do_cert_wait");
    return false;
  }

  memcpy(server_key_comm.data(),
         transcript.data() + transcript.size() - hash_size,
         sizeof(server_key_comm));

  TRACK_IF_INTERESTED(Events::State::CERT_WAIT,
                      sizeof(Messaging::MessageHeaders) + sizeof(uint64_t) +
                          transcript.size());

  transcript.resize(transcript.size() - hash_size);

  // Now we can just move on.
  this->state = next_state(this->state);
  return true;
}

bool Server::write_cert_recv() noexcept {
  TIME(Events::State::CERT_WRITE);
  // We write out a single header followed by the SHTS and CHTS.
  // Note that we've already recovered the value of fk_s and the other secets,
  // which we'll check before we derive the traffic secrets.
  bssl::Array<uint8_t> out_arr;
  const auto size = sizeof(Messaging::MessageHeaders) +
                    handshake_key_shares.SHTS_share.size() +
                    handshake_key_shares.CHTS_share.size();

  if (!out_arr.Init(size)) {
    PRINT_IF_LOUD("Failed to create buffer in write_cert_recv");
    return false;
  }

  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), size) ||
      !CBB_add_u8(cbb.get(),
                  static_cast<uint8_t>(
                      Messaging::MessageHeaders::CERTIFICATE_CTX_RECV)) ||
      !CBB_add_bytes(cbb.get(), handshake_key_shares.CHTS_share.data(),
                     handshake_key_shares.CHTS_share.size()) ||
      !CBB_add_bytes(cbb.get(), handshake_key_shares.SHTS_share.data(),
                     handshake_key_shares.SHTS_share.size()) ||
      !CBBFinishArray(cbb.get(), &out_arr)) {
    PRINT_IF_LOUD("Failed to serialise into buffer in write_cert_recv");
    return false;
  }

  // Write it.
  if (!socket.write(out_arr.data(), out_arr.size())) {
    PRINT_IF_LOUD("Failed to write shares in write_cert_recv");
    return false;
  }

  TRACK_IF_INTERESTED(Events::State::CERT_WRITE, size);
  this->state = next_state(this->state);
  return true;
}

bool Server::do_ks() noexcept {
  // We just call into the circuit routine directly here: there's no need to
  // update anything.
  TIME(Events::State::KS_WAIT);

  // With that updated, we can actually run the key derivation circuit.
  // The key derivation circuit only requires _us_ to provide the input mask,
  // which is generated inside the circuit calling function.
  EmpWrapperAG2PCConstants::HandshakeCircuitIn input{};

  // Populate the input.
  if (!input.key_share.CopyFrom(x_secret)) {
    PRINT_IF_LOUD("Failed to copy key share in do_ks");
    return false;
  }

  // Clear the counter if we're interested in tracking.
  if constexpr (BandwidthTracker::TrackerType::is_interested(
                    Events::State::KS_WAIT)) {
    handshake_circuits[active_key_share]->reset_counter();
  }

  // N.B the hardcoded true means "we are the verifier"
  if (!ThreePartyHandshake::run_handshake_circuit(
          input, handshake_key_shares,
          handshake_circuits[active_key_share].get(), true)) {
    PRINT_IF_LOUD("Failed to run handshake circuit in do_ks");
    return false;
  }

  TRACK_IF_INTERESTED(Events::State::KS_WAIT,
                      handshake_circuits[active_key_share]->get_counter());
  // Free old memory. This can be substantial.
  handshake_circuits[active_key_share].reset(nullptr);
  this->state = next_state(this->state);
  return true;
}

bool Server::write_ks_done() noexcept {
  TIME(Events::State::KS_DONE);
  TRACK_IF_INTERESTED(Events::State::KS_DONE,
                      sizeof(Messaging::MessageHeaders));
  // We'll just write a single header.
  if (!write_single_header(socket, Messaging::MessageHeaders::KS_DONE)) {
    PRINT_IF_LOUD("Failed to write ks_done in write_ks_done");
    return false;
  }

  // We're done with the KS!
  this->state = next_state(this->state);
  return true;
}

bool Server::read_h6() noexcept {
  // Read in the hash so far.
  if (!read_transcript_data(socket, buffer, h6,
                            Messaging::MessageHeaders::H6_SEND, *this)) {
    PRINT_IF_LOUD("Failed to read h6 in read_h6");
    return false;
  }
  this->state = next_state(this->state);
  return true;
}

bool Server::write_h6_recv() noexcept {
  if (!write_single_header(socket, Messaging::MessageHeaders::H6_RECV)) {
    PRINT_IF_LOUD("Failed to write h6_recv in write_h6_recv");
    return false;
  }
  this->state = next_state(this->state);
  return true;
}

bool Server::derive_ts() noexcept {
  TIME(Events::State::DERIVE_TS);

  // The first thing to do is to read the header from the other party.
  // This is just a single byte to indicate that they want to derive
  // traffic secrets.
  Messaging::MessageHeaders header;
  if (!read_single_header(socket, header) ||
      header != Messaging::MessageHeaders::DERIVE_TS) {
    PRINT_IF_LOUD("Failed to read derive_ts header in derive_ts");
    return false;
  }

  // Now we just call into the joint derivation circuit with the relevant
  // information.
  EmpWrapperAG2PCConstants::TrafficCircuitIn input{};
  input.ms_share = handshake_key_shares.MS_share;

  [[maybe_unused]] const auto old_amount = traffic_circuit->get_counter();

  // Call into the traffic secrets circuit. The hardcoded "true" means "we are
  // the verifier".
  if (!ThreePartyHandshake::run_traffic_circuit(input, traffic_key_shares,
                                                traffic_circuit.get(), true)) {
    PRINT_IF_LOUD("Failed to run traffic secret circuit in derive_ts");
    return false;
  }

  TRACK_IF_INTERESTED(Events::State::DERIVE_TS,
                      traffic_circuit->get_counter() - old_amount);

  // The shares we need are actually written directly into storage, so we don't
  // need to unpack here (i.e we can just move on to the next state).
  this->state = next_state(this->state);
  return true;
}

bool Server::derive_gcm_shares() noexcept {
  TIME(Events::State::DERIVE_GCM_SHARES);
  // In this state we wait for the prover to issue the write to
  // us and then go from there.
  Messaging::MessageHeaders header;
  if (!read_single_header(socket, header) ||
      header != Messaging::MessageHeaders::GCM_SHARE_START) {
    PRINT_IF_LOUD("Failed to read GCM_SHARE_START in derive_gcm_shares");
    return false;
  }

  // Call into the GCM derivation functions. The main bulk of the work is
  // actually handled in the 3PH routine, which also derives all of the relevant
  // circuitry code too.
  // As before, the bulk of the storage for this function is stored in the class
  // itself.
  PRINT_IF_LOUD("Calling into derivation circuit");
  uint64_t bandwidth;
  if (!ThreePartyHandshake::make_gcm_shares(
          socket.get_ssl_object(), traffic_key_shares.client_key_share,
          traffic_key_shares.server_key_share, gcm_circuit.get(),
          client_gcm_powers, server_gcm_powers, &bandwidth)) {
    PRINT_IF_LOUD("Failed to make gcm shares in derive_gcm_shares");
    return false;
  }

  TRACK_IF_INTERESTED(Events::State::DERIVE_GCM_SHARES, bandwidth);

  // Move on to the next state.
  this->state = next_state(this->state);
  return true;
}

bool Server::write_completed_derivation() noexcept {
  if (!write_single_header(socket, Messaging::MessageHeaders::GCM_SHARE_DONE)) {
    PRINT_IF_LOUD(
        "Failed to write GCM_SHARE_DONE in write_completed_derivation");
    return false;
  }
  this->state = next_state(this->state);
  return true;
}

bool Server::attest() noexcept {
  Messaging::MessageHeaders header;
  bool worked = true;
  while (worked) {
    // Read the single header in from the other party.
    if (!read_single_header(socket, header)) {
      return false;
    }

    switch (header) {
    case Messaging::MessageHeaders::STOP:
      return true;
    case Messaging::MessageHeaders::AES_ENC:
      break;
    case Messaging::MessageHeaders::AES_DEC:
      break;
    case Messaging::MessageHeaders::COMMIT:
      break;
    default:
      worked = false;
      break;
    }
  }
  return worked;
}

bool Server::run(const ServerState stop_state, const bool print,
                 const bool should_preproc) {
  /*
     This is a standard intepreter loop for dispatching into functions
     dependent on state. This only works because the server is a single
     connection entity. Note that loops of this kind have been subject to many
     optimisations, and so if this turns out to be too slow (for whatever
     reason) there's lots we can do here.

     The way this loop works is as follows. We store all state (e.g all read
     variables etc) as member variables in this server. We then (in an ideal
     situation) walk through the switch in order: we first accept, then
     handshake etc etc. If we fail at any step we return an error to the
     caller. We'll also write an error to the connecting client if there's an
     actionable error: for example, if the key share that was sent to us isn't
     what we expected, or if some error occurs.
  */

  // Reset the state
  this->state = ServerState::ACCEPT;
  this->loud = print;
  bool was_successful;
  while (!should_stop(this->state, stop_state)) {
    switch (this->state) {
    case ServerState::ACCEPT:
      PRINT_IF_LOUD("Accepting");
      was_successful = accept();
      break;
    case ServerState::HANDSHAKE:
      PRINT_IF_LOUD("Doing handshake");
      was_successful = do_handshake();
      break;
    case ServerState::HANDSHAKE_DONE:
      PRINT_IF_LOUD("Finished handshake");
      was_successful = write_handshake_done();
      break;
    case ServerState::READING_KS:
      PRINT_IF_LOUD("Reading key share");
      was_successful = read_keyshare_after_handshake();
      break;
    case ServerState::MAKING_KS:
      PRINT_IF_LOUD("Creating key share");
      was_successful = create_new_share();
      break;
    case ServerState::CIRCUIT_PREPROC:
      PRINT_IF_LOUD("Preprocessing circuits");
      was_successful = do_preproc(should_preproc);
      break;
    case ServerState::WRITING_KS:
      PRINT_IF_LOUD("Writing key share");
      was_successful = send_additive_share();
      break;
    case ServerState::READING_SKS:
      PRINT_IF_LOUD("Reading server key share");
      was_successful = read_sks_keyshare();
      break;
    case ServerState::FINISHING_TPH:
      PRINT_IF_LOUD("Finishing 3PH");
      was_successful = finish_tph();
      break;
    case ServerState::READING_PSSKS:
      assert(false);
      std::abort();
    case ServerState::WRITING_HS_RECV:
      PRINT_IF_LOUD("Writing HS_RECV");
      was_successful = write_hs_recv();
      break;
    case ServerState::ECTF_WAIT:
      PRINT_IF_LOUD("Doing ectf");
      was_successful = do_ectf();
      break;
    case ServerState::ECTF_DONE:
      PRINT_IF_LOUD("Finished ectf");
      was_successful = finish_ectf();
      break;
    case ServerState::KS_WAIT:
      PRINT_IF_LOUD("Doing HS derivation");
      was_successful = do_ks();
      break;
    case ServerState::KS_DONE:
      PRINT_IF_LOUD("Finished HS derivation");
      was_successful = write_ks_done();
      break;
    case ServerState::CERT_WAIT:
      PRINT_IF_LOUD("Reading cert");
      was_successful = do_cert_wait();
      break;
    case ServerState::CERT_RECV:
      PRINT_IF_LOUD("Read cert");
      was_successful = write_cert_recv();
      break;
    case ServerState::H6_WAIT:
      PRINT_IF_LOUD("Reading H6");
      was_successful = read_h6();
      break;
    case ServerState::H6_RECV:
      PRINT_IF_LOUD("Written H6 RECV");
      was_successful = write_h6_recv();
      break;
    case ServerState::DERIVE_TS:
      PRINT_IF_LOUD("Deriving TS");
      was_successful = derive_ts();
      break;
    case ServerState::GCM_SHARE_DERIVE:
      PRINT_IF_LOUD("Deriving GCM shares");
      was_successful = derive_gcm_shares();
      break;
    case ServerState::GCM_SHARE_DONE:
      PRINT_IF_LOUD("Derived GCM shares");
      was_successful = write_completed_derivation();
      break;
    default:
      // We terminate here, because this implies a logic error on our
      // part.
      // Note: in a release build we could make this an unreachable.
      std::abort();
    }

    if (!was_successful) {
      break;
    }
  }

  if (print) {
    std::cerr << "TIMINGS:" << std::endl;
    timer.print();
    std::cerr << "DATA:" << std::endl;
    bandwidth_tracker.print();
  }

  if (was_successful && should_attest) {
    // We loop here for a bit.
    while (attest())
      ;
  }

  return was_successful;
}

SSL_CTX *Server::get_ctx() noexcept { return ssl_ctx.get(); }
const bssl::Array<uint8_t> &Server::get_x_secret() const noexcept {
  return x_secret;
}

void Server::set_attestation() noexcept { should_attest = true; }

#undef TRACK_IF_INTERESTED
#undef TIME
#undef MACRO_CONCAT
#undef CONCAT_IMPL
#undef PRINT_IF_LOUD

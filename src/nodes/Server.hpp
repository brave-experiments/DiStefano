#ifndef INCLUDED_SERVER_HPP
#define INCLUDED_SERVER_HPP

#include "../mta/ectf.hpp"            // Needed for ECTF operations.
#include "../ssl/EmpWrapperAG2PC.hpp" // Needed for layout.
#include "../ssl/TLSSocket.hpp"       // Needed for TLS connections.
#include "BandwidthTracker.hpp"
#include "KeyShare.hpp" // Needed for key share work.
#include "Timer.hpp"

/**
   Server. This class contains a server object. This is meant to represent a
server in the TLS attestation protocol.

Please note that this class contains some untested methods. This is primarily
for situations where providing open tests would break this class' encapsulation.
These methods are primarily wrappers around functions that the socket provides:
as a result, these functions are (by proxy) tested in the socket's test suite.
**/

class Server {
public:
  enum class ServerState : uint8_t {
    /**
       ACCEPT. The server is waiting for an incoming connection.
       Next action here is to accept a new connection.
    **/
    ACCEPT = 0,
    /**
       HANDSHAKE. The server has accepted a connection. The next step
       is to handshake with the new connection.
    **/
    HANDSHAKE = 1,
    /**
       HANDSHAKE_DONE. The server has done the handshake. We now need to tell
    the client that it worked.
    **/
    HANDSHAKE_DONE = 2,
    /**
       READING_KS. The server has done the handshake. The next step is to read
       the key share.
    **/
    READING_KS = 3,
    /**
       MAKING_KS. The server has read the client's key share. The next step
       is to make a new one of our own.
    **/
    MAKING_KS = 4,

    /**
       CIRCUIT_PREPROC. We've made our own key share. The next step is to
       run circuit preprocessing, if applicable.
    **/
    CIRCUIT_PREPROC = 5,

    /**
       WRITING_KS. The server has successfully made a key share. The next step
       is to write our own out.
    **/
    WRITING_KS = 6,

    /**
       READING_SKS. The server is now waiting for the client to send over the
    other parties' key share.
    **/
    READING_SKS = 7,

    /**
       READING_PSSKS. The server has just received a pre-shared key-share from
       the client.
     **/
    READING_PSSKS = 8,

    /**
       FINISHING_TPH. The server has read the other parties' key share and is
       now processing it.
    **/
    FINISHING_TPH = 9,

    /**
       WRITING_HS_RECV. The server has read the other parties' key share and
     processed it. The server now writes a message saying it has done so.
     **/
    WRITING_HS_RECV = 10,

    /**
       ECTF_WAIT. The server has written the acknowledgement of receiving the
    key share and read the transcript. The server is now waiting to do the ECTF
    work.
    **/
    ECTF_WAIT = 11,

    /**
       ECTF_DONE. The server has finished the ECTF protocol. The server writes a
    message to the prover to mention that it has finished.
    **/
    ECTF_DONE = 12,

    /**
       KS_WAIT. The server is waiting for the updated transcript from the
    client.
    **/
    KS_WAIT = 13,

    /**
       KS_DONE. The server has advanced the key schedule. The server writes a
     message to the prover to mention that it has finished.
     **/
    KS_DONE = 14,

    /**
       CERT_WAIT. The server is waiting for the prover to commit to the
    certificate.
    **/
    CERT_WAIT = 15,

    CERT_RECV = 16,

    H6_WAIT = 17,
    H6_RECV = 18,

    DERIVE_TS = 19,

    GCM_SHARE_DERIVE = 20,
    GCM_SHARE_DONE = 21,

    /**
       DONE. We're done.
    **/
    DONE = 22,

    /**
       SIZE. This is the number of elements in the enumeration.
    **/
    SIZE = 23,
  };

  /**
     Server. This constructor accepts an rvalue unique ptr to a SSL_CTX, an
  ip_address, a boolean denoting whether the address is an ip v4 address, and a
  backlog parameter, and builds `this` server.

     @snippet Server.t.cpp ServerConstructorTests
     @param[in] ctx: the SSL_CTX for `this` server.
     @param[in] ip_address: the ip_address to bind to.
     @param[in] is_ip_v6: true if the `ip_address` is ip_v6, false otherwise.
     @param[in] backlog: the number of backlogged connections to accept.
  **/
  Server(bssl::UniquePtr<SSL_CTX> &&ctx, const std::string &ip_address,
         const bool is_ip_v6, const int backlog) noexcept;

  /**
     run. This function runs the Server's code. In particular, this function
     is responsible for doing a single handshake->generating key share run.
     If at any step this function fails, then this function will return `false`.
     Otherwise, this function will return `true`.

     @snippet Server.t.cpp ServerRunTests
     @param[in] stop_state: the state in which to stop the loop. Mostly
     only useful for testing.
     @param[in] print: true if the server should print stats, false otherwise.
  Only useful for testing.
     @param[in] should_preproc: true if the server should run circuit
  preprocessing, false otherwise. False is only useful during testing.
     @return true in case of success, false otherwise.
  **/
  bool run(const ServerState stop_state = ServerState::DONE,
           const bool print = false, const bool should_preproc = true);

  /**
     create_new_public_key. This function accepts a `curve_id` corresponding
     to an elliptic curve and generates a new public key for `this` server
     using the curve. This function returns true on success and false otherwise.

     This function fails if:
     1) `curve_id` doesn't correspond to a valid elliptic curve.
     2) generating the public key somehow fails.

     This function does not throw.

     @snippet Server.t.cpp ServerCreatePublicKeyTests

     @param[in] curve_id: the identifier for the curve.
     @return true in case of success, false otherwise.
     @remarks At present we do not support the non-NIST curves. This may change
  in future.
  **/
  bool create_new_public_key(const uint16_t curve_id) noexcept;

  /**
     send_additive_share. This function serialises `this` socket's additive
  share across the TLSSocket. This function returns true on success and false on
  error. This function will return false if:
     1. Packing the key bytes fails.
     2. Writing the bytes fails.

     This function does not throw.
     @snippet Server.t.cpp ServerSendAdditiveShareTests
     @return true in case of success, false otherwise.
  **/
  bool send_additive_share();
  /**
     accept. This function accepts a new connection for `this` socket. This
   function returns true on success and false on an error.

     This function does not throw.
     @return true if a new connection succeeds, false otherwise.
   **/
  bool accept() noexcept;
  /**
     do_handshake. This function runs a SSL handshake between `this` socket and
  a new connection. This function returns true on success and false on an error.
     This function does not throw.
     @return true in case of success, false otherwise.
  **/
  bool do_handshake() noexcept;

  /**
     read_keyshare_after_handshake. This function reads the keyshare from
  another node after the handshake has occurred. This function returns true on
  success and false on an error. This function does not throw.
     @return true in case of success, false otherwise.
  **/
  bool read_keyshare_after_handshake() noexcept;

  /**
     read_sks_keyshare. This function reads the keyshare from
  another node. This corresponds to reading the key bytes of a third party.
  This function returns true on
  success and false on an error. This function does not throw.
  @return true in case of success, false otherwise.
  **/
  bool read_sks_keyshare() noexcept;

  /**
     get_curve_ids. This function returns the curve ID of each key share in an
  array. In particular, this array is {key_shares[0]'s curve ID, key_share[1]'s
  curve_ID}. If key_shares[i] is not initialised, then the ith position of the
  array shall be equal to 1. This function does not throw and does not modify
  this object.
     @snippet Server.t.cpp ServerGetCurveIDTests
     @return an array containing the curve ids.
  **/
  std::array<uint16_t, 2> get_curve_ids() const noexcept;

  /**
     create_new_share. This function accepts a public key
  corresponding to another node (`other_key_bytes`) and computes a new additive
  share for those key shares. The exact semantics of this are a bit confusing.

     Please note that calling this function causes a new public key to be
  generated for `this` server.

     This function returns false if:
     1. the call to Server::create_new_public_key fails.
     2. adding the two public keys together fails.
     3. exporting the public keys fails as a series of bytes fails.

     This function does not throw.
     @snippet Server.t.cpp ServerCreateNewShareTests
     @param[in] other_key_bytes: the public key of the other node.
     @return true in case of success, false otherwise.
  **/
  bool create_new_share(const bssl::Array<uint8_t> &other_key_bytes) noexcept;

  /**
     create_new_share. This function is a wrapper function for calling the other
     create_new_share method. This function simply calls the other
  create_new_share method with `this` socket's client_curve_id and
  client_public_key respectively.

     @return true in case of success, false otherwise.
  **/
  bool create_new_share() noexcept;

  bool do_preproc(const bool should_preproc) noexcept;

  /**
     finish_tph. This function finishes the three party handshake. In
  particular, this function computes the shared key share from the received key
  share (from Server::read_sks_keyshare). This function does not throw.

     This function will return false if:
     1. the received key share is invalid.
     2. if the received key share does not match either key share held by this
  object.

     @return true if successful, false otherwise.
  **/
  bool finish_tph() noexcept;

  /**
     write_hs_recv. This function writes an acknowledgement to the client that
     the handshake was received and completed successfully. This function
     returns true if the write was successful and false otherwise. In
  particular, this function returns false if:

     1. writing the header fails.

     This function does not throw.
     @return true if successful, false otherwise.
  **/
  bool write_hs_recv() noexcept;

  /**
     do_ectf. This function carries out the ECtF functionality provided by
  mta/ECtF.hpp. Essentially, this function produces additive shares of the `x`
  co-ordinate of the shared key, which is then used for the TLS PRF. This
  function does not throw.
     @return true in case of success, false otherwise.
  **/
  bool do_ectf() noexcept;

  /**
     finish_ectf. This function writes an acknowledgement to the client that
     the ectf has finished successfully. This function returns true if the write
     was successful and false otherwise.

     This function does not throw.
     @return true if successful, false otherwise.
  **/
  bool finish_ectf() noexcept;

  /**
     get_portnumber. This function writes a copy of `this` socket's port number
  to the `out` parameter. This function returns true when successful and false
  otherwise.

     This function will fail unless:
     1. There has been a successful binding (see StatefulSocket::bind for more).
     2. The out pointer is non-null.

     This function does not modify `this` object and does not throw.
     @param[out] out: the location to write the port number.
     @return true on success, false otherwise.
  **/
  bool get_portnumber(uint16_t *const out) const noexcept;

  /**
     write_handshake_done. This function writes a simple DONE_HS message to
  `this` socket's connection. This function returns true in case of success and
  false otherwise.

     @snippet Server.t.cpp ServerWriteHandshakeDoneTests
     @return true if successful, false otherwise.
  **/
  bool write_handshake_done() noexcept;

  /**
     get_ctx. This function returns a copy of the SSL_CTX that's associated with
  `this` socket. This function does not throw any exceptions and does not modify
  `this` socket directly: however, as the returned pointer is not const, then
  this method cannot be const.
     @return a copy of `this` object's SSL_CTX.
  **/
  SSL_CTX *get_ctx() noexcept;

  /**
    get_additive_share. This function writes a copy of `this` server's
 additive share to the `arr` parameter. This function returns `true` if the
 write is successful and false otherwise.
    This function will fail if:
    1. resizing the input `arr` fails.
    This function will return true even if an additive share has not yet been
 generated. This will manifest as `arr` being an array of size 0.
    This function does not modify `this` object and does not throw.
    @snippet Server.t.cpp ServerGetAdditiveShareTests
    @param[out] arr: the array to overwrite. This will throw away any previous
    data in the array.
    @return true in case of success, false otherwise.
 **/
  bool get_additive_share(bssl::Array<uint8_t> &arr) const noexcept;
  /**
  get_public_key.
  This function writes a copy of `this` server's public key to the `arr`
  parameter.This function returns `true` if the write is successful and false
  otherwise .This function will fail if:
  1. resizing the input `arr` fails.

  This function will return true even if a public key has not yet been
  generated. This will manifest as `arr` being an array of size 0. This function
  does not modify `this` object and does not throw.

  @snippet Server.t.cpp ServerGetPublicKeyTests
  @param[out] arr: the array to overwrite. This will throw away any previous
  data in the array.
  @return true in case of success, false otherwise.
  **/
  bool get_public_key(bssl::Array<uint8_t> &arr) const noexcept;

  /**
   **/
  SSL *get_ssl();

  KeyShare &get_active_share();

  const bssl::Array<uint8_t> &get_x_secret() const noexcept;

  /**
     do_ks. This function reads the handshake transcript from the prover and
  stores the result in `transcript`. This is then used to advance the key
  schedule using the `x` secret. This function
  **/
  bool do_ks() noexcept;

  bool do_cert_wait() noexcept;
  bool write_cert_recv() noexcept;

  bool write_ks_done() noexcept;

  bool read_h6() noexcept;
  bool write_h6_recv() noexcept;

  bool derive_ts() noexcept;
  bool derive_gcm_shares() noexcept;
  bool write_completed_derivation() noexcept;

  void set_version(const uint16_t version) noexcept;
  void set_cipher_suite(const uint16_t cipher_suite) noexcept;

  void set_attestation() noexcept;

  bool attest() noexcept;

private:
  /**
     ssl_ctx. This is a pointer to the SSL_CTX that
     controls the socket's SSL object. `this` server
     owns the context.
  **/
  bssl::UniquePtr<SSL_CTX> ssl_ctx;

  /**
     shares. This is a pointer to the server's share object.
     Here, `share` means "the BoringSSL KeyShare object":
     this is just responsible for generating keys that are involved in the TLS
  attestation process.
  **/

  KeyShare key_shares[2];

  /**
     public_key. This contains `this` server's current public key in a
  serialised format. This will be empty in some circumstances.
  **/
  bssl::Array<uint8_t> public_key;
  /**
     additive_share. This contains `this` server's additive share of the 3 party
  handshake key. This will be empty in some circumstances.
  **/
  bssl::Array<uint8_t> additive_share;
  /**
     state. This contains `this` server's current state inside the Server::run
  function. See ServerState for more.
  **/
  ServerState state;

  /**
     active_key_share. This variable denotes the current active key share. This
  variable only has any meaning after `finish_tph`.
  **/
  unsigned int active_key_share;

  // This is the state read from the client

  /**
     client_public_key. This contains the serialised public key from the client.
  **/
  bssl::Array<uint8_t> client_public_key;
  /**
     client_group_id. This contains the group ID of the public key from the
  client.
  **/
  uint16_t client_group_id;

  /**
     ret_code. This contains the current BoringSSL return code from any
  BoringSSL operations. This exists to make it easier to debug the code.
  **/
  int ret_code;

  /**
     socket. This is the TLS socke that's used for communications.
  **/
  TLSSocket socket;

  /**
     buffer. This contains the serialised public key from the client prior to
     parsing. More broadly, this contains any "peeked" message.
     This exists to save on heap allocations.
  **/
  bssl::Array<uint8_t> buffer;

  /**
     x_secret. This contains the produced x_secret that's used in the TLS PRF.
  **/
  bssl::Array<uint8_t> x_secret;

  /**
     transcript. This contains the transcript read from the prover at various
   stages in the protocol.
   **/
  std::vector<uint8_t> transcript;

  std::vector<uint8_t> h6;

  bssl::SSLTranscript transcript_obj;
  EmpWrapperAG2PCConstants::HandshakeCircuitOut handshake_key_shares;
  EmpWrapperAG2PCConstants::TrafficCircuitOut traffic_key_shares;
  EmpWrapperAG2PCConstants::AESGCMBulkShareType client_gcm_powers;
  EmpWrapperAG2PCConstants::AESGCMBulkShareType server_gcm_powers;

  uint16_t version;
  uint16_t cipher_suite;

  bool was_sf_right;

  /**
     timer. This object is used to record how long the various events that occur
  during the TLS handshake take. Each event can be found in Events.hpp.
  **/
  Timer::TimerType timer;

  /**
     bandwidth_tracker. This object is used to track how much bandwidth is
  consumed during various parts of this program. Each event can be found in
  Events.hpp.
  **/
  BandwidthTracker::TrackerType bandwidth_tracker;

  std::array<std::unique_ptr<EmpWrapperAG2PC>, 2> handshake_circuits;
  std::unique_ptr<EmpWrapperAG2PC> traffic_circuit;
  std::unique_ptr<EmpWrapperAG2PC> aes_split_circuit;
  std::unique_ptr<EmpWrapperAG2PC> aes_joint_circuit;
  std::unique_ptr<EmpWrapperAG2PC> gcm_circuit;

  std::array<uint8_t, 32> server_key_comm;

  bool should_attest{false};
  bool loud{false};
};

#endif

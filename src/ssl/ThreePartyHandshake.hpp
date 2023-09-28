#ifndef INCLUDED_THREEPARTYHANDSHAKE_HPP
#define INCLUDED_THREEPARTYHANDSHAKE_HPP

#include "EmpWrapperAG2PC.hpp" // Needed for circuit out
#include "openssl/base.h" // This only contains the forward declarations for SSL* etc.
#include "ssl/internal.h" // This contains the declaration for Array.
#include <cstdint>

/**
 * @brief ThreePartyHandshake. This namespace contains a series  of functions
 *for doing TLS 1.3 Three Party Handshakes.
 *
 * This namespace is a bit weird. This is to get around certain quirks / design
 *choices in BoringSSL. For example, BoringSSL makes it really hard to overwrite
 *fields that have already been set-up (which is a good thing!) but it makes it
 * difficult for us to do a three-party handshake.
 *
 * To get around this, we re-use parts of BoringSSL to do the handshake.
 * Precisely, we establish a connection between the prover and verifier,
 * generate the keyshares on the prover and send the shares to the verifier in
 * application data. The verifier then takes those key shares and uses
 * BoringSSL's key establishment code to compute their part of the local shares.
 *
 * @remarks Note that we have to use a C-style OOP construct here. Precisely,
 * functions like three_party_handshake_comm() have to take their owner as a
 * parameter. This is because C doesn't have implicit "this" sadly. This also
 * means we can't use other C++ features like exceptions (everything has to be
 *an error code).
 **/
namespace ThreePartyHandshake {

/**
   @brief handshake_function_type. This is a public declaration for the
   function pointer we use for the three-party handshake hook.
   This is placed here to make it easier for users of this namespace
   to get the function type without needing to dig deeply into BoringSSL.
**/
using handshake_function_type = SSL::key_share_callback_function_type;

/**
   @brief send_key_share_function_type. This is a public declaration
   for the function pointer that we use to send the received key share from
   the server back to the verifier. This is placed here to make it easier
   for users of this namespace to get the function type without needing to dig
   deeply back into BoringSSL.
**/
using send_key_share_function_type =
    SSL::key_share_received_callback_function_type;

/**
   @brief derive_shared_secret_function_type. This is a public declaration for
the function pointer that we use to derive the shared master secret in TLS. This
is placed here to make it easier for users of this namespace to get the function
type without needing to dig deeply back into BoringSSL.
**/
using derive_shared_secret_function_type =
    SSL::derive_shared_secret_function_type;

/**
   @brief derive_handshake_secrets_function_type. This is a public declaration
   for the function pointer that we use to derive handshake secrets in TLS. This
   is placed here to make it easier for users of this namespace to get the
function type without needing to dig deeply back into BoringSSL.
**/
using derive_handshake_secrets_function_type =
    SSL::derive_shared_secret_function_type;

/**
   @brief derive_handshake_keys_function_type. This is a public declaration
   for the function pointer that we use to derive handshake keys in TLS. This
   is placed here to make it easier for users of this namespace to get the
function type without needing to dig deeply back into BoringSSL.
**/
using derive_handshake_keys_function_type =
    SSL::derive_handshake_keys_function_type;

using commit_to_server_certificate_function_type =
    SSL::commit_to_server_certificate_function_type;
using write_h6_function_type = SSL::write_h6_function_type;

/**
     @brief derive_traffic_keys_function_type. This is a public declaration for
the function pointer that we use to derive shares of the traffic secrets in TLS.
This is palced here to make it easier for users of this namespace to get the
function type without needing to dig deeply back into BoringSSL.
**/
using derive_traffic_keys_function_type =
    SSL::derive_traffic_keys_function_type;

using derive_gcm_shares_function_type = SSL::derive_gcm_shares_function_type;

/**
 * @brief three_party_handshake_comm. This function accepts an SSL object
 * (representing a current SSL connection) and (using that SSL object's
 * `verifier`) contacts a third party in order to generate shared keyshares.
 * Concretely, this function forwards the SSL object's `hs` values to another
 * party, who then replies with a new set of `hs` values for the SSL object to
 * use in the outgoing handshake. This function returns true in case of
 * success and false in case of error.
 * @snippet ThreePartyHandshake.t.cpp ThreePartyHandshakeCommTests
 *
 * @param ssl: the ssl object to be modified.
 * @param hs: the ssl handshake object.
 * @returns true if the key shares change, false otherwise.
 */
bool three_party_handshake_comm(SSL *ssl, bssl::SSL_HANDSHAKE *hs);

/**
 @brief three_party_handshake_send_received_key_shares. This function accepts an
SSL object (representing a current SSL connection) and (using that's SSL
object's `verifier`) forwards the received key share on to a third party.
Concretely, this part of the handshake is the sending of the received key share
from the `server` on to the `verifier`. This function returns true in case of
success and false in case of error.

 @snippet ThreePartyHandshake.t.cpp ThreePartyHandshakeHSKSTests
 @param[in] ssl: the SSL object.
 @param[in] group_id: the ID of the elliptic curve.
 @param[in] cbs: the CBS that contains the data.
 @return true if `this` connection receives a "HS_RECV" message, false
otherwise.
**/
bool three_party_handshake_send_received_key_shares(SSL *ssl, uint16_t group_id,
                                                    CBS &cbs);

/**
   derived_shared_key_master_secret. This function accepts an SSL object
(representing a current SSL connection) and (using that SSL object's `verifier`)
derives a shared secret.

Concretely, this part of the handshake is the 2PC derivation of the shared
secret between the prover and the verifier. This function does not throw and
returns true in the case of success, false otherwise.

@param[in] hs: the handshake object.
@param[in] ssl: the SSL object.
@param[in] secret: the y-coordinate of the secret.
@return true in case of success, false otherwise.
**/
bool derive_shared_master_secret(bssl::SSL_HANDSHAKE *hs, SSL *ssl,
                                 bssl::Array<uint8_t> &secret);

/**
   advance_key_schedule. This function accepts an SSL object (representing a
current SSL connection) and (using that SSL object's `verifier`) advances the
key schedule for both parties. Concretely, this takes place by forwarding the
buffer from the `hs` to the `verifier` and by calling ssl_advance_key_share on
the prover. This function returns true in case of success and false
otherwise.
   @param[in] hs: the handshake object.
   @param[in] ssl: the SSL object.
   @param[in] secret: the derived secret.
   @return true in case of success, false otherwise.
**/
bool advance_key_schedule(bssl::SSL_HANDSHAKE *hs, SSL *ssl,
                          bssl::Array<uint8_t> &secret);

/**
   derive_handshake_secret. This function accepts an SSL object (representing a
current SSL connection) and (using that SSL object's `verifier`) derives a
handshake traffic secret. Concretely, this function runs the ECtF portion of the
protocol.

@param[in] hs: the handshake object.
@param[in] ssl: the SSL object.
@param[in] secret: the x-coordinate of the derived secret.
@return true in case of success, false otherwise.
**/

bool derive_handshake_secret(bssl::SSL_HANDSHAKE *hs, SSL *ssl,
                             bssl::Array<uint8_t> &secret);
/**
   Concretely, this part of the handshake is the 2PC
derivation of the handshake traffic secrets: this function derives the HS, CHTS,
SHTS and dHS shares. In addition, this function also derives both sets of
handshake keys and IVs: these are distributed depending on the caller.
**/
bool derive_handshake_keys(bssl::SSL_HANDSHAKE *hs, SSL *ssl,
                           bssl::Array<uint8_t> &secret);

bool derive_traffic_keys(bssl::SSL_HANDSHAKE *hs, SSL *ssl);

bool commit_to_server_certificate(bssl::SSL_HANDSHAKE *hs, SSL *ssl);
bool write_h6(SSL *ssl, bssl::Span<uint8_t> hash);

bool aes_encrypt(SSL *const ssl, bssl::Array<uint8_t> &in,
                 bssl::Array<uint8_t> &out) noexcept;
bool aes_decrypt(SSL *const ssl, bssl::Array<uint8_t> &in,
                 bssl::Array<uint8_t> &out) noexcept;

bool commit_to(SSL *const ssl, const bssl::Array<uint8_t> &blocks,
               const bssl::Array<unsigned> &blocks_to_commit_to,
               bssl::Array<uint8_t> &commitment) noexcept;

bool make_gcm_shares(SSL *const ssl, const std::array<uint8_t, 16> &ckey_share,
                     const std::array<uint8_t, 16> &skey_share,
                     EmpWrapperAG2PC *const circuit,
                     EmpWrapperAG2PCConstants::AESGCMBulkShareType &cgcm_share,
                     EmpWrapperAG2PCConstants::AESGCMBulkShareType &sgcm_share,
                     uint64_t *bandwidth) noexcept;

bool derive_gcm_shares(SSL *const ssl) noexcept;

bool run_handshake_circuit(
    const EmpWrapperAG2PCConstants::HandshakeCircuitIn &in,
    EmpWrapperAG2PCConstants::HandshakeCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept;

bool run_traffic_circuit(const EmpWrapperAG2PCConstants::TrafficCircuitIn &in,
                         EmpWrapperAG2PCConstants::TrafficCircuitOut &out,
                         EmpWrapperAG2PC *const circuit,
                         const bool verifier) noexcept;
} // namespace ThreePartyHandshake

/**
   This section of the file contains some checks to make sure that everything
 lines up. The compiler will also complain, but this makes life easier
 (friendlier error messages).
 **/

static_assert(
    std::is_same_v<decltype(&ThreePartyHandshake::three_party_handshake_comm),
                   ThreePartyHandshake::handshake_function_type>,
    "Error: three_party_handshake_comm does not match "
    "handshake_function_type");

static_assert(
    std::is_same_v<decltype(&ThreePartyHandshake::
                                three_party_handshake_send_received_key_shares),
                   ThreePartyHandshake::send_key_share_function_type>,
    "Error: three_party_send_received_key_shares does not match "
    "send_key_share_function_type");

static_assert(
    std::is_same_v<decltype(&ThreePartyHandshake::derive_shared_master_secret),
                   ThreePartyHandshake::derive_shared_secret_function_type>,
    "Error: derive_shared_master_secret does not match "
    "derive_shared_secret_function_type");

static_assert(
    std::is_same_v<decltype(&ThreePartyHandshake::derive_handshake_secret),
                   ThreePartyHandshake::derive_handshake_secrets_function_type>,
    "Error: derive_handshake_secret does not match "
    "derive_handshake_secrets_function_type");

#endif

#ifndef INCLUDED_MESSAGING_HPP
#define INCLUDED_MESSAGING_HPP

#include "openssl/base.h" // This only contains the forward declarations for SSL* etc.
#include "ssl/internal.h" // This contains the declaration for Array.
#include <cstdint>

/**
 * @brief Messaging. This namespace represents a namespace for doing Messaging
 *operations. In particular, this namespace is concerned with translating
 *bytestreams into messages that can be understood by any party inside this
 *program.
 **/

namespace Messaging {
/**
@brief MessageHeaders. This enum class contains the headers that messages in
the ThreePartyHandshake use. These are deliberately constrained to be 8 bits:
this is to reduce bandwidth.
**/
enum class MessageHeaders : std::uint8_t {
  /**
     COLLECT. This header indicates the message was sent from a prover to a
  verifier. This message will contain TLS key shares that are to be adjusted.
  **/
  COLLECT = 0,
  /**
     OK. This header indicates the message was sent from a verifier to the
   prover. This message contains the new TLS key shares that are to be used in
   the three party handshake.
   **/
  OK = 1,

  /**
     DONE_HS. This header indicates a successful initial SSL handshake has been
  completed from the verifier's side. This is a signal for the prover to send
  over their TLS key shares.
  **/
  DONE_HS = 2,

  /**
     SERVER_KEY_SHARE. This header indicates that this message contains the
     `server's` key share, sent from the `prover` to the `verifier`.
  **/
  SERVER_KEY_SHARE = 3,

  /**
     HS_RECV. This header indicates that this message contains an
  acknowledgement from the `verifier` that it has received and used the
  `server's` key share.
  **/
  HS_RECV = 4,

  /**
     DO_ECTF. This header indicates that this message should start the ECtF
  functionality. This will only be sent after HS_RECV has been received.
  **/
  DO_ECTF = 5,

  /**
     ECTF_DONE. This header indicates that this message contains an
  acknowledgement from the `verifier` that it has finished the ECTF with the
  prover.
  **/
  ECTF_DONE = 6,

  /**
     ADVANCE_KS. This header indicates that this message contains the transcript
   of the handshake, which is to be used to advance the key schedule. This is
   sent by the prover to the verifier.
   **/
  ADVANCE_KS = 7,

  /**
     KS_DONE. This header indicates that the verifier has advanced their key
  schedule successfully.
   **/
  KS_DONE = 8,

  /**
     TRANSCRIPT_INIT. This header indicates that this message is the first part
  of the transcript from the prover to the verifier.
  **/
  TRANSCRIPT_INIT = 9,

  /**
     TRANSCRIPT_INIT_DONE. This header indicates that the verifier successfully
  processed the initial transcript from the prover.
  **/
  TRANSCRIPT_INIT_DONE = 10,

  CERTIFICATE_CTX_SEND = 11,
  CERTIFICATE_CTX_RECV = 12,
  H6_SEND = 13,
  H6_RECV = 14,

  DERIVE_TS = 16,

  GCM_SHARE_START = 17,
  GCM_SHARE_DONE = 18,

  COMMIT = 19,
  COMMIT_TO = 20,

  AES_ENC = 21,
  AES_DEC = 22,

  STOP = 23,

  /**
     SIZE. This contains the number of elements in the enum. This should ideally
  be last in the enum. Note that this will also signify an invalid header in
  certain settings.
  **/
  SIZE = 21,
};

/**
 @brief header_size. This constant contains the number of bytes needed to
contain the minimal information for each message. This should not vary across
machines as the header comprises of machine independent types.
**/
static constexpr auto header_size = sizeof(MessageHeaders);

/**
   is_valid_header. This function accepts an 8-bit integer and returns true if
   `header` corresponds to a valid MessageHeader and false otherwise. This
function does not throw.
   @param[in] header: the 8-bit value to check.
   @return true if header corresponds to a MessageHeader, false otherwise.
**/
constexpr bool is_valid_header(const std::uint8_t header) noexcept;

/**
 @brief pack_key_bytes. This function accepts a Span of bytes
(corresponding to key bytes) and formats the bytes for serialisation, writing
the result to the `out` parameter.

 In particular, this function returns an array of bytes corresponding to:
 1) An 8 bit integer, containing the `header` argument,
 2) The bytes of the keying material.

 This function returns true on success and false on error.

 If this function is supplied with an array of size 0, then this function will
return false. Note that this function can also encode at most
SSL3_RT_MAX_PLAIN_LENGTH bytes. Because of the pre-packing we provide, this
means that `key_share_bytes` can contain at most SSL3_RT_MAX_PLAIN_LENGTH - 1
bytes. If `key_share_bytes` exceeds this length then false will be returned.

 @snippet Messaging.t.cpp MessagingPackKeyBytesTests

 @param[in] header: the message header to send.
 @param[in] key_share_bytes: a reference to the keying bytes.
 @param[out] out: a reference to an output array.
 @return true on success, false on error.
**/
bool pack_key_bytes(const MessageHeaders header,
                    const bssl::Span<const uint8_t> key_share_bytes,
                    bssl::Array<uint8_t> &out);

/**
 @brief pack_key_bytes. This function accepts an OpenSSL array of bytes
(corresponding to key bytes) and formats the bytes for serialisation, writing
the result to the `out` parameter.

 In particular, this function returns an array of bytes corresponding to:
 1) An 8 bit integer, containing the `header` argument,
 2) The bytes of the keying material.

 This function returns true on success and false on error.

 If this function is supplied with an array of size 0, it will return false.
 This is primarily for error checking. Note that this
 function can also encode at most SSL3_RT_MAX_PLAIN_LENGTH bytes. Because
 of the pre-packing we provide, this means that `key_share_bytes` can
 contain at most SSL3_RT_MAX_PLAIN_LENGTH - 1 bytes. If `key_share_bytes`
 exceeds this length then false will be returned.

 @snippet Messaging.t.cpp MessagingPackKeyBytesTests

 @param[in] header: the message header to send.
 @param[in] key_share_bytes: a reference to the keying bytes.
 @param[out] out: a reference to an output array.
 @return true on success, false on error.
**/
bool pack_key_bytes(const MessageHeaders header,
                    const bssl::Array<uint8_t> &key_share_bytes,
                    bssl::Array<uint8_t> &out);

/**
   @brief unpack_key_bytes. This function accepts a Span of bytes
 (corresponding to a message), parses the contents and writes the result to
 the `out` parameter.

   In particular, this function:
   1) Checks the initial 8 bit header.
   2) Copies the rest of the message into a new array and returns the new
 array.

   This function returns true on success and false on failures.

   This function will return false in the following circumstances:
   1) If `input` is an array of size 0.
   2) If `input` has a size larger than SSL3_RT_MAX_PLAIN_LENGTH.
   4) If the first 8 bits do not correspond to a valid header.
   5) If `input` is an array of size header_size.

   @snippet Messaging.t.cpp MessagingUnpackKeyBytesTests
   @param[out] out_header: the location to store the header.
   @param[in] input: the array to read from.
   @param[out] out: the location to write the output.
   @return true on success, false on error.
 **/
bool unpack_key_bytes(MessageHeaders &out_header,
                      const bssl::Span<const uint8_t> input,
                      bssl::Array<uint8_t> &out);

/**
 @brief unpack_key_bytes. This function accepts an OpenSSL array of bytes
(corresponding to a message), parses the contents and writes the result to
the `out` parameter.

 In particular, this function:
 1. Checks the initial 8 bit header.
 2. Copies the rest of the message into a new array and returns the new
array.

 This function returns true on success and false on failures.

 This function will return false in the following circumstances:
 1. If `input` is an array of size 0.
 2. If `input` has a size larger than SSL3_RT_MAX_PLAIN_LENGTH.
 3. If the first 8 bits do not correspond to a valid header.
 4. If `input` is an array of size header_size.
 5. If the size read from `input` does not match the size of the `input`
array.

 @param[out] out_header: the location to store the header.
 @param[in] input: the array to read from.
 @param[out] out: the location to write the output.
 @return true on success, false on error.
**/
bool unpack_key_bytes(MessageHeaders &out_header,
                      const bssl::Array<uint8_t> &input,
                      bssl::Array<uint8_t> &out);
} // namespace Messaging

#include "Messaging.inl"
#endif

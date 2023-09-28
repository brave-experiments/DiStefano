#include "Messaging.hpp"
#include <iostream>

bool Messaging::pack_key_bytes(const Messaging::MessageHeaders header,
                               const bssl::Array<uint8_t> &key_share_bytes,
                               bssl::Array<uint8_t> &out) {
  return Messaging::pack_key_bytes(
      header, bssl::MakeSpan(key_share_bytes.data(), key_share_bytes.size()),
      out);
}

bool Messaging::pack_key_bytes(const Messaging::MessageHeaders header,
                               const bssl::Span<const uint8_t> key_share_bytes,
                               bssl::Array<uint8_t> &out) {
  if (key_share_bytes.size() == 0 ||
      key_share_bytes.size() > SSL3_RT_MAX_PLAIN_LENGTH - sizeof(header)) {
    return false;
  }

  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), header_size + key_share_bytes.size())) {
    return false;
  }

  // We don't want this to silently break.
  static_assert(sizeof(header) == sizeof(uint8_t),
                "Error: sizeof(header) is no longer sizeof(uint8_t)");

  if (!CBB_add_u8(cbb.get(), static_cast<uint8_t>(header)) ||
      !CBB_add_bytes(cbb.get(), key_share_bytes.data(),
                     sizeof(uint8_t) * key_share_bytes.size())) {
    return false;
  }

  return CBBFinishArray(cbb.get(), &out);
}

bool Messaging::unpack_key_bytes(Messaging::MessageHeaders &out_header,
                                 const bssl::Array<uint8_t> &input,
                                 bssl::Array<uint8_t> &out) {
  return Messaging::unpack_key_bytes(
      out_header, bssl::MakeSpan(input.data(), input.size()), out);
}

bool Messaging::unpack_key_bytes(Messaging::MessageHeaders &out_header,
                                 const bssl::Span<const uint8_t> input,
                                 bssl::Array<uint8_t> &out) {
  if (input.size() == 0 || input.size() > SSL3_RT_MAX_PLAIN_LENGTH ||
      input.size() < Messaging::header_size + 1) {
    return false;
  }

  CBS in_cbs;
  CBS_init(&in_cbs, input.data(), input.size());

  // Now it's time to unpack the keying material. We do this by first
  // checking the first 8 bits to make sure they correspond to a valid message.
  std::uint8_t header;
  if (!CBS_get_u8(&in_cbs, &header) || !is_valid_header(header)) {
    return false;
  }

  // Store the header.
  out_header = static_cast<Messaging::MessageHeaders>(header);

  // Finally we've gotten some data to extract out into our key bytes.
  return out.Init(input.size() - sizeof(header)) &&
         CBS_copy_bytes(&in_cbs, out.data(), out.size() * sizeof(uint8_t)) == 1;
}

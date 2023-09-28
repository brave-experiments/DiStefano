#include "../doctest.h"
#include "Messaging.hpp"

//! [MessagingIsValidHeaderTests]
TEST_CASE("MessagingIsValidHeaderTests") {
  // Manually check all of the values we expect to pass.
  REQUIRE(Messaging::is_valid_header(
      static_cast<uint8_t>(Messaging::MessageHeaders::OK)));
  REQUIRE(Messaging::is_valid_header(
      static_cast<uint8_t>(Messaging::MessageHeaders::COLLECT)));
  REQUIRE(Messaging::is_valid_header(
      static_cast<uint8_t>(Messaging::MessageHeaders::DONE_HS)));
  REQUIRE(Messaging::is_valid_header(
      static_cast<uint8_t>(Messaging::MessageHeaders::SERVER_KEY_SHARE)));
  REQUIRE(Messaging::is_valid_header(
      static_cast<uint8_t>(Messaging::MessageHeaders::HS_RECV)));

  // This fails because it isn't a header we'd expect to see "in the wild".
  REQUIRE(!Messaging::is_valid_header(
      static_cast<uint8_t>(Messaging::MessageHeaders::SIZE)));

  // N.B this loop is mostly to make sure that if we miss a header from the
  // manual listing above that we still cover the enum. This only works if the
  // enum's entries are all < SIZE!
  for (uint8_t i = 0; i < static_cast<uint8_t>(Messaging::MessageHeaders::SIZE);
       i++) {
    CHECK(Messaging::is_valid_header(i));
  }

  // And this loop makes sure we fail all other values.
  constexpr auto maximum = std::numeric_limits<uint8_t>::max();
  for (uint8_t i = static_cast<uint8_t>(Messaging::MessageHeaders::SIZE) + 1;
       i < maximum; i++) {
    CHECK(!Messaging::is_valid_header(i));
  }
}

//! [MessagingIsValidHeaderTests]

//! [MessagingPackKeyBytesTests]
TEST_CASE("MessagingPackKeyBytes") {
  bssl::Array<uint8_t> arr;
  // Yes, this is likely to be a poor
  // source of randomness. But this is probably good enough.
  // N.B the +1 is to prevent 0-length arrays.
  const auto random = static_cast<std::size_t>(rand() % 4096) + 1;
  arr.Init(random);
  for (unsigned i = 0; i < random; i++) {
    arr[i] = static_cast<uint8_t>(rand());
  }

  bssl::Array<uint8_t> out;

  SUBCASE("Empty arrays returns false") {
    bssl::Array<uint8_t> arr2;
    REQUIRE(arr2.size() == 0);
    CHECK(!Messaging::pack_key_bytes(Messaging::MessageHeaders::COLLECT,
                                     bssl::MakeSpan(arr2.data(), arr2.size()),
                                     out));
  }

  SUBCASE("Passing in a too large array returns false") {
    bssl::Array<uint8_t> arr2;
    arr2.Init(SSL3_RT_MAX_PLAIN_LENGTH);
    CHECK(!Messaging::pack_key_bytes(Messaging::MessageHeaders::COLLECT,
                                     bssl::MakeSpan(arr2.data(), arr2.size()),
                                     out));
  }

  SUBCASE("Passing in a non-zero length array will return without failure") {
    CHECK(Messaging::pack_key_bytes(Messaging::MessageHeaders::COLLECT,
                                    bssl::MakeSpan(arr.data(), arr.size()),
                                    out));
    // We'd really expect this not to be of length 0.
    CHECK(out.size() != 0);
    // We can be more precise
    constexpr auto header_len = sizeof(Messaging::MessageHeaders);
    CHECK(out.size() == header_len + sizeof(int8_t) * random);
    // Now we'll convert the array into a CBS, so we can do the correct
    // decoding.
    CBS in_cbs;
    // We have to initialise the CBS from the array we produced.
    CBS_init(&in_cbs, out.data(), out.size());

    std::uint8_t header;
    REQUIRE(CBS_get_u8(&in_cbs, &header));
    CHECK(header == static_cast<uint8_t>(Messaging::MessageHeaders::COLLECT));

    const auto size = out.size() - sizeof(Messaging::header_size);

    uint8_t curr;
    for (uint32_t i = 0; i < size; i++) {
      REQUIRE(CBS_get_u8(&in_cbs, &curr));
      CHECK(curr == arr[i]);
    }
  }
}
//! [MessagingPackKeyBytesTests]

//! [MessagingUnpackKeyBytesTests]
TEST_CASE("MessagingUnpackKeyBytes") {
  bssl::Array<uint8_t> input, out;
  auto header = Messaging::MessageHeaders::SIZE;
  SUBCASE("Calling unpack_key_bytes with an empty array fails") {
    CHECK(!Messaging::unpack_key_bytes(
        header, bssl::MakeSpan(input.data(), input.size()), out));
  }

  SUBCASE("Calling unpack_key_bytes with an array that is too large fails") {
    input.Init(SSL3_RT_MAX_PLAIN_LENGTH + 1);
    CHECK(!Messaging::unpack_key_bytes(
        header, bssl::MakeSpan(input.data(), input.size()), out));
  }

  SUBCASE("Calling unpack_key_bytes with a message that is too small fails") {
    input.Init(Messaging::header_size);
    CHECK(!Messaging::unpack_key_bytes(
        header, bssl::MakeSpan(input.data(), input.size()), out));
  }

  SUBCASE("Calling unpack_key_bytes with a malformed header fails") {
    input.Init(Messaging::header_size + 1);
    input[0] = static_cast<uint8_t>(Messaging::MessageHeaders::SIZE);
    CHECK(!Messaging::unpack_key_bytes(
        header, bssl::MakeSpan(input.data(), input.size()), out));
  }

  bssl::Array<uint8_t> arr;
  bssl::ScopedCBB cbb;
  REQUIRE(CBB_init(cbb.get(), SSL3_RT_MAX_PLAIN_LENGTH));
  REQUIRE(CBB_add_u8(cbb.get(),
                     static_cast<uint8_t>(Messaging::MessageHeaders::COLLECT)));

  SUBCASE("Calling unpack_key_bytes with the right size works") {
    REQUIRE(CBB_add_u8(cbb.get(), 5));
    REQUIRE(CBB_add_u8(cbb.get(), 7));
    REQUIRE(CBB_add_u8(cbb.get(), 9));
    REQUIRE(CBBFinishArray(cbb.get(), &arr));

    CHECK(Messaging::unpack_key_bytes(header, arr, out));
    REQUIRE(out.size() == 3);
    CHECK(out[0] == 5);
    CHECK(out[1] == 7);
    CHECK(out[2] == 9);
  }
}
//! [MessagingUnpackKeyBytesTests]

TEST_CASE("unpack_key_bytes and pack_key_bytes work together") {
  bssl::Array<uint8_t> input, packed, unpacked;
  const std::uint32_t size = static_cast<uint32_t>(rand() % 4096 + 1);
  input.Init(size);

  auto header = Messaging::MessageHeaders::SIZE;
  // Generate some random input.
  for (unsigned i = 0; i < size; i++) {
    input[i] = static_cast<uint8_t>(rand());
  }

  REQUIRE(Messaging::pack_key_bytes(Messaging::MessageHeaders::COLLECT,
                                    bssl::MakeSpan(input.data(), input.size()),
                                    packed));
  REQUIRE(Messaging::unpack_key_bytes(
      header, bssl::MakeSpan(packed.data(), packed.size()), unpacked));
  CHECK(header == Messaging::MessageHeaders::COLLECT);
  REQUIRE(unpacked.size() == input.size());
  for (unsigned i = 0; i < unpacked.size(); i++) {
    CHECK(unpacked[i] == input[i]);
  }
}

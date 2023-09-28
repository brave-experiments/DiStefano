#include "../doctest.h"
#include "MessageHeaders.hpp"
#include <limits>

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

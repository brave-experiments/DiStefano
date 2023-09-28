#include "../doctest.h"
#include "SSLBuffer.hpp"

// These should always be true.
static_assert(SSLBuffer::can_buffer());
static_assert(SSLBuffer::has_data());

//! [SSLBufferDefaultParams]
TEST_CASE("SSLBufferDefaultParams") {
  SSLBuffer buffer{};
  CHECK(buffer.size() == 0);
  CHECK(buffer.capacity() == 0);
}
//! [SSLBufferDefaultParams]

//! [SSLBufferReserve]
TEST_CASE("reserve") {
  SSLBuffer buffer{};
  buffer.reserve(10);
  CHECK(buffer.size() == 0);
  CHECK(buffer.capacity() >= 10);
}
//! [SSLBufferReserve]

//! [SSLBufferInsert]
TEST_CASE("insert") {
  SSLBuffer buffer{};
  char data = 5;
  buffer.buffer_data(&data, sizeof(data));
  CHECK(buffer.size() == 1);
  CHECK(*buffer.data() == data);

  SUBCASE("clear") {
    buffer.clear();
    CHECK(buffer.size() == 0);
  }
}
//! [SSLBufferInsert]

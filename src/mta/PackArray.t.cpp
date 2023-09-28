#include "PackArray.hpp"
#include "../doctest.h"
#include <cstdlib>
#include <cstring>

//! [PackArrayDefaultConstructor]
TEST_CASE("default_constructor") {
  PackArray ptr{};
  CHECK(ptr.size() == 0);
  CHECK(ptr.data() == nullptr);
  CHECK(ptr.empty());
  CHECK(ptr.size_in_bytes() == 0);
}
//! [PackArrayDefaultConstructor]

//! [PackArraySizeOnlyConstructor]
TEST_CASE("size_only_constructor") {
  const size_t size = static_cast<size_t>(rand() % 40);
  PackArray ptr{size};
  CHECK(ptr.size() == size);
  CHECK(ptr.size_in_bytes() == size * sizeof(uint8_t));
}
//! [PackArraySizeOnlyConstructor]

//! [PackArrayInit]
TEST_CASE("init") {
  const size_t size = static_cast<size_t>(rand() % 40);

  SUBCASE("init on empty span works") {
    PackArray ptr{};
    CHECK(ptr.size() == 0);
    ptr.init(size);
    CHECK(ptr.size() == size);
  }

  PackArray ptr{size};
  REQUIRE(ptr.size() == size);

  SUBCASE("init with a 0 nulls out the span") {
    ptr.init(0);
    CHECK(ptr.data() == nullptr);
    CHECK(ptr.size() == 0);
  }

  SUBCASE("init on already allocated span works") {
    size_t size_2 = 0;

    // This is just to make sure we don't end up with
    // a useless test.
    do {
      size_2 = static_cast<size_t>(rand() % 40);
    } while (size_2 != size);

    ptr.init(size_2);
    CHECK(ptr.size() == size_2);
  }
}

//! [PackArrayBegin]
TEST_CASE("begin") {
  const size_t size = static_cast<size_t>(rand() % 40);
  PackArray ptr{size};
  CHECK(ptr.size() == size);
  CHECK(ptr.data() == ptr.begin());
  CHECK(ptr.data() == ptr.cbegin());
}
//! [PackArrayBegin]

TEST_CASE("end") {
  // Declare some random data first.
  const size_t size = static_cast<size_t>(rand() % 40);
  PackArray ptr(size);
  CHECK(ptr.end() == ptr.begin() + size);
  CHECK(ptr.cend() == ptr.cbegin() + size);
}
//! [PackArrayEnd]

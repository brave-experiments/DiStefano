#include "../doctest.h"
#include "EmpBlockSpan.hpp"
#include <cstdlib>
#include <cstring>

//! [EmpBlockSpanDefaultConstructor]
TEST_CASE("default_constructor") {
  EmpBlockOwningSpan ptr{};
  CHECK(ptr.size() == 0);
  CHECK(ptr.data() == nullptr);
  CHECK(ptr.empty());
  CHECK(ptr.size_in_bytes() == 0);
}
//! [EmpBlockOwningSpanDefaultConstructor]

//! [EmpBlockOwningSpanElementConstructor]
TEST_CASE("default constructor with args") {
  // Declare some random data first.
  const size_t size = static_cast<size_t>(rand() % 40);
  emp::block *block = new emp::block[size]();
  EmpBlockOwningSpan ptr(block, size);
  CHECK(ptr.size() == size);
  CHECK(ptr.data() == block);
  CHECK(!ptr.empty());
}
//! [EmpBlockOwningSpanElementConstructor]

//! [EmpBlockCopyConstructor]
TEST_CASE("copy_constructor") {
  // Declare some random data first.
  const size_t size = static_cast<size_t>(rand() % 40);
  emp::block *block = new emp::block[size]();
  // Randomise it 8 bits at a time.
  char *data = reinterpret_cast<char *>(block);

  const auto scaling = sizeof(emp::block);

  for (unsigned i = 0; i < size * scaling; i++) {
    data[i] = static_cast<char>(rand());
  }

  // Now create the owner.
  EmpBlockOwningSpan ptr(block, size);

  // Now we'll copy it
  EmpBlockOwningSpan ptr2(ptr);
  CHECK(ptr2.size() == ptr.size());
  CHECK(memcmp(ptr2.data(), ptr.data(), sizeof(emp::block) * size) == 0);
  CHECK(ptr2.data() != ptr.data());
}
//! [EmpBlockCopyConstructor]

//! [EmpBlockInit]
TEST_CASE("init") {
  const size_t size = static_cast<size_t>(rand() % 40);

  SUBCASE("init on empty span works") {
    EmpBlockOwningSpan ptr{};
    CHECK(ptr.size() == 0);
    ptr.init(size);
    CHECK(ptr.size() == size);
  }

  EmpBlockOwningSpan ptr{size};
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

//! [EmpBlockBegin]
TEST_CASE("begin") {
  const size_t size = static_cast<size_t>(rand() % 40);
  EmpBlockOwningSpan ptr{size};
  CHECK(ptr.size() == size);
  CHECK(ptr.data() == ptr.begin());
  CHECK(ptr.data() == ptr.cbegin());
}
//! [EmpBlockBegin]

//! [EmpBlockEnd]
TEST_CASE("end") {
  // Declare some random data first.
  const size_t size = static_cast<size_t>(rand() % 40);
  emp::block *block = new emp::block[size]();
  EmpBlockOwningSpan ptr(block, size);
  CHECK(ptr.data() == block);
  CHECK(ptr.end() == block + size);
  CHECK(ptr.cend() == block + size);
}
//! [EmpBlockEnd]

//! [EmpBlockAccessors]
TEST_CASE("accessors") {
  // Declare some random data first.
  const size_t size = static_cast<size_t>(rand() % 40);
  emp::block *block = new emp::block[size]();
  // Randomise it 8 bits at a time.
  char *data = reinterpret_cast<char *>(block);

  const auto scaling = sizeof(emp::block);

  for (unsigned i = 0; i < size * scaling; i++) {
    data[i] = static_cast<char>(rand());
  }

  // Now create the owner.
  EmpBlockOwningSpan ptr(block, size);

  // Again, check that the data lined up.
  CHECK(ptr.data() == block);
  // And now we'll check that the first and last blocks match.
  CHECK(memcmp(&ptr.front(), &block[0], sizeof(emp::block)) == 0);
  CHECK(memcmp(&ptr.back(), &block[size - 1], sizeof(emp::block)) == 0);

  // And finally we'll iterate over everything.
  for (unsigned i = 0; i < size; i++) {
    CHECK(memcmp(&ptr[i], &block[i], sizeof(emp::block)) == 0);
  }
}
//! [EmpBlockAccessors]

#include "../doctest.h"
#include "EmpBlockSpan.hpp"
#include <cstdlib>
#include <cstring>

//! [EmpBlockNonNonOwningSpanDefaultConstructor]
TEST_CASE("default_constructor") {
  EmpBlockNonOwningSpan ptr{};
  CHECK(ptr.size() == 0);
  CHECK(ptr.data() == nullptr);
  CHECK(ptr.empty());
  CHECK(ptr.size_in_bytes() == 0);
}
//! [EmpBlockNonOwningSpanDefaultConstructor]

//! [EmpBlockNonOwningSpanElementConstructor]
TEST_CASE("default constructor with args") {
  // Declare some random data first.
  const size_t size = static_cast<size_t>(rand() % 40);
  emp::block *block = new emp::block[size]();
  EmpBlockNonOwningSpan ptr(block, size);
  CHECK(ptr.size() == size);
  CHECK(ptr.data() == block);
  CHECK(!ptr.empty());
  // We have to delete it here, because ptr doesn't own block.
  delete[] block;
}
//! [EmpBlockNonOwningSpanElementConstructor]

//! [EmpBlockNonOwningBegin]
TEST_CASE("begin") {
  const size_t size = static_cast<size_t>(rand() % 40);
  emp::block *block = new emp::block[size]();
  EmpBlockNonOwningSpan ptr{block, size};
  CHECK(ptr.size() == size);
  CHECK(ptr.data() == ptr.begin());
  CHECK(ptr.data() == ptr.cbegin());
  delete[] block;
}
//! [EmpBlockBegin]

//! [EmpBlockEnd]
TEST_CASE("end") {
  // Declare some random data first.
  const size_t size = static_cast<size_t>(rand() % 40);
  emp::block *block = new emp::block[size]();
  EmpBlockNonOwningSpan ptr(block, size);
  CHECK(ptr.data() == block);
  CHECK(ptr.end() == block + size);
  CHECK(ptr.cend() == block + size);
  delete[] block;
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
  EmpBlockNonOwningSpan ptr(block, size);

  // Again, check that the data lined up.
  CHECK(ptr.data() == block);
  // And now we'll check that the first and last blocks match.
  CHECK(memcmp(&ptr.front(), &block[0], sizeof(emp::block)) == 0);
  CHECK(memcmp(&ptr.back(), &block[size - 1], sizeof(emp::block)) == 0);

  // And finally we'll iterate over everything.
  for (unsigned i = 0; i < size; i++) {
    CHECK(memcmp(&ptr[i], &block[i], sizeof(emp::block)) == 0);
  }
  delete[] block;
}
//! [EmpBlockAccessors]

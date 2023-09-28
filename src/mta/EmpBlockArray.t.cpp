#include "EmpBlockArray.hpp"
#include "../doctest.h"

//! [EmpBlockArraySize]
TEST_CASE("emp_array_size") {
  // First of all we statically check the size of such an object
  static_assert(sizeof(EmpBlockArray<10>) == sizeof(emp::block) * 10,
                "Error: basic size check fails");
  static_assert(sizeof(EmpBlockArray<4>) == sizeof(emp::block) * 4,
                "Error: basic size check fails");
  static_assert(sizeof(EmpBlockArray<1>) == sizeof(emp::block) * 1,
                "Error: basic size check fails");

  // Now we'll check that size() returns the right thing.
  EmpBlockArray<100> a;
  CHECK(a.size() == 100);
}
//! [EmpBlockArraySize]

//! [EmpBlockArrayDefaultConstruct]
TEST_CASE("default-construct") {
  EmpBlockArray<128> a{};
  CHECK(a.size() == 128);
}
//! [EmpBlockArrayDefaultConstruct]

//! [EmpBlockArrayData]
TEST_CASE("data") {
  EmpBlockArray<100> a{};
  // Not null
  CHECK(a.data() != nullptr);
  // Same address as the base object.
  CHECK(reinterpret_cast<const char *>(a.data()) ==
        reinterpret_cast<const char *>(&a));

  // Works on const types too.
  const EmpBlockArray<100> b{};
  // Not null
  CHECK(b.data() != nullptr);
  // Same address as the base object.
  CHECK(reinterpret_cast<const char *>(b.data()) ==
        reinterpret_cast<const char *>(&b));
}
//! [EmpBlockArrayData]

//! [EmpBlockArrayOperator[]]
TEST_CASE("operator[]") {
  EmpBlockArray<100> a{};
  // Check that the retrieved index is where we expect it to be.
  for (unsigned i = 0; i < 100; i++) {
    CHECK(reinterpret_cast<unsigned char *>(&a[i]) ==
          reinterpret_cast<unsigned char *>(&a) + sizeof(emp::block) * i);
  }

  // Check the same for a const reference.
  const EmpBlockArray<100> b{};
  for (unsigned i = 0; i < 100; i++) {
    CHECK(reinterpret_cast<const unsigned char *>(&b[i]) ==
          reinterpret_cast<const unsigned char *>(&b) + sizeof(emp::block) * i);
  }
}
//! [EmpBlockArrayOperator[]]

//! [EmpBlockArrayBegin]
TEST_CASE("begin") {
  EmpBlockArray<100> a{};
  // Here we're allowed a direct pointer-iterator comparison.
  CHECK(a.begin() == &a[0]);
}
//! [EmpBlockArrayBegin]

//! [EmpBlockArrayCBegin]
TEST_CASE("cbegin") {
  EmpBlockArray<100> a{};
  // Here we're allowed a direct pointer-iterator comparison.
  CHECK(a.cbegin() == &a[0]);
  // The addresses are the same.
  CHECK(a.cbegin() == a.begin());
}
//! [EmpBlockArrayCBegin]

//! [EmpBlockArrayEnd]
TEST_CASE("begin") {
  constexpr unsigned size = 100;
  EmpBlockArray<size> a{};
  // Here we're allowed a direct pointer-iterator comparison.
  // Note the -1: it exists to allow us to do this test without reading
  // potentially uninitialised memory.
  CHECK(a.end() - 1 == &a[size - 1]);
}
//! [EmpBlockArrayEnd]

//! [EmpBlockArrayCEnd]
TEST_CASE("cend") {
  constexpr unsigned size = 100;
  EmpBlockArray<size> a{};
  // Note the -1: it exists to allow us to do this test without reading
  // potentially uninitialised memory.
  CHECK(a.end() - 1 == &a[size - 1]);
  // These addresses are the same.
  CHECK(a.cend() == a.end());
}
//! [EmpBlockArrayCBegin]

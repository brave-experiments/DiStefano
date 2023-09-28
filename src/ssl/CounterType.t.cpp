#include "../doctest.h"
#include "CounterType.hpp"
#include <cstdlib>
#include <cstring>

//! [RWCounterGetRead]
TEST_CASE("get_read") {
  // Warning: this is a hack. This relies upon knowing the exact memory layout
  // of the underlying counter type. Naturally, this could break.
  RWCounter counter{};
  static_assert(sizeof(counter) == 2 * sizeof(std::size_t),
                "Error: sizeof(RWCounter) has changed.");
  std::size_t raw[2];
  // Copy over into the array.
  memcpy(raw, &counter, sizeof(raw));
  // Check that it indeed initially started at 0.
  CHECK(raw[0] == 0);
  CHECK(raw[1] == 0);

  // Now copy back over but with a different counter.
  raw[0] = static_cast<std::size_t>(rand());
  raw[1] = static_cast<std::size_t>(rand());
  memcpy(&counter, raw, sizeof(raw));
  CHECK(counter.get_read() == raw[0]);
}
//! [RWCounterGetRead]

//! [RWCounterGetWrite]
TEST_CASE("get_write") {
  // Warning: this is a hack. This relies upon knowing the exact memory layout
  // of the underlying counter type. Naturally, this could break.
  RWCounter counter{};
  static_assert(sizeof(counter) == 2 * sizeof(std::size_t),
                "Error: sizeof(RWCounter) has changed.");
  std::size_t raw[2];
  // Copy over into the array.
  memcpy(raw, &counter, sizeof(raw));
  // Check that it indeed initially started at 0.
  CHECK(raw[0] == 0);
  CHECK(raw[1] == 0);

  // Now copy back over but with a different counter.
  raw[0] = static_cast<std::size_t>(rand());
  memcpy(&counter, raw, sizeof(raw));
  CHECK(counter.get_write() == raw[1]);
}
//! [RWCounterGetWrite]

//! [RWCounterTrackWrite]
TEST_CASE("track_write") {
  RWCounter counter{};
  REQUIRE(counter.get_write() == 0);

  SUBCASE("Works") {
    const std::size_t tmp1 = static_cast<std::size_t>(rand());
    counter.track_write(tmp1);
    SUBCASE("Invariant") {
      CHECK(counter.get_write() == tmp1);
      CHECK(counter.get_write() == tmp1);
    }
    SUBCASE("multiple") {
      const std::size_t tmp2 = static_cast<std::size_t>(rand());
      counter.track_write(tmp2);
      CHECK(counter.get_write() == tmp1 + tmp2);
    }

    //! [RWCounterResetWrite]
    SUBCASE("reset_write") {
      REQUIRE(counter.get_write() != 0);
      counter.reset_write();
      CHECK(counter.get_write() == 0);
    }
    //! [RWCounterResetWrite]
  }
}
//! [RWCounterTrackWrite]

//! [RWCounterTrackRead]
TEST_CASE("track_read") {
  RWCounter counter{};
  REQUIRE(counter.get_read() == 0);

  SUBCASE("Works") {
    const std::size_t tmp1 = static_cast<std::size_t>(rand());
    counter.track_read(tmp1);
    SUBCASE("Invariant") {
      CHECK(counter.get_read() == tmp1);
      CHECK(counter.get_read() == tmp1);
    }
    SUBCASE("multiple") {
      const std::size_t tmp2 = static_cast<std::size_t>(rand());
      counter.track_read(tmp2);
      CHECK(counter.get_read() == tmp1 + tmp2);
    }

    //! [RWCounterResetRead]
    SUBCASE("reset_read") {
      REQUIRE(counter.get_read() != 0);
      counter.reset_read();
      CHECK(counter.get_read() == 0);
    }
    //! [RWCounterResetRead]
  }
}
//! [RWCounterTrackRead]

//! [NoCounterGetRead]
TEST_CASE("get_read") {
  NoCounter counter{};
  static_assert(counter.get_read() == 0,
                "Error: counter did not return 0 from get_read");
}
//! [NoCounterGetRead]

//! [NoCounterGetWrite]
TEST_CASE("get_write") {
  NoCounter counter{};
  static_assert(counter.get_write() == 0,
                "Error: counter did not return 0 from get_write");
}
//! [NoCounterGetWrite]

//! [NoCounterTrackWrite]
TEST_CASE("track_write") {
  NoCounter counter{};
  CHECK(counter.get_write() == 0);
  counter.track_write(100);
  CHECK(counter.get_write() == 0);
}
//! [NoCounterTrackWrite]

//! [NoCounterTrackRead]
TEST_CASE("track_read") {
  NoCounter counter{};
  CHECK(counter.get_read() == 0);
  counter.track_read(100);
  CHECK(counter.get_read() == 0);
}
//! [NoCounterTrackRead]

//! [NoCounterResetRead]
TEST_CASE("reset_read") {
  NoCounter counter{};
  CHECK(counter.get_read() == 0);
  counter.reset_read();
  CHECK(counter.get_read() == 0);
}
//! [NoCounterResetRead]

//! [NoCounterResetWrite]
TEST_CASE("reset_write") {
  NoCounter counter{};
  CHECK(counter.get_write() == 0);
  counter.reset_write();
  CHECK(counter.get_write() == 0);
}
//! [NoCounterResetWrite]

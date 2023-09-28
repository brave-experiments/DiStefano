#ifndef INCLUDED_BANDWIDTHTRACKER_HPP
#define INCLUDED_BANDWIDTHTRACKER_HPP

#include "Events.hpp"
#include <array>
#include <cstdint>
#include <iostream>

/**
   BandwidthTracker. This namespace includes trackers for tracking certain
bandwidth events that may be useful. This is primarily used for gathering data
that might be useful for performance optimisations and investigations.
**/
namespace BandwidthTracker {
/**
   ActiveTracker. This class records all bandwidth events in an array.
**/
class ActiveTracker {
public:
  static constexpr bool is_interested(const Events::State) noexcept {
    return true;
  }

  uint64_t *get_memory_for(const Events::State state) noexcept {
    return &data[static_cast<unsigned>(state)];
  }

  void print() const noexcept {
    for (unsigned i = 0; i < static_cast<unsigned>(Events::State::SIZE); i++) {
      std::cerr << Events::as_string[i] << ":"
                << static_cast<double>(data[i]) / (1024. * 1024.) << " MB\n";
    }
    std::cerr << "\n";
  }

private:
  std::array<uint64_t, static_cast<unsigned>(Events::State::SIZE)> data;
};

/**
   NoTracker. This class records nothing.
**/
class NoTracker {
public:
  static constexpr bool is_interested(const Events::State) noexcept {
    return false;
  }

  uint64_t *get_memory_for(const Events::State) const noexcept {
    return nullptr;
  }

  void print() const noexcept {}
};

using TrackerType = ActiveTracker;

} // namespace BandwidthTracker

#endif

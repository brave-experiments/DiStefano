#ifndef INCLUDED_TIMER_HPP
#define INCLUDED_TIMER_HPP

#include<array>
#include<chrono>
#include<cstdint>
#include<iostream>

#include "Events.hpp"

/**
   Timer. This namespace implements a series of counters for tracking how long certain events take inside the protocol.
   Essentially, this namespace contains two different counters that do different things. As you may expect, the NoTimer
   does nothing (all operations are no-ops) whereas the ActiveTimer counts all events.
**/
namespace Timer {

  class ActiveTimer {
    std::array<std::chrono::duration<double>,
               static_cast<unsigned>(Events::State::SIZE)>
        times{};
    std::array<std::chrono::time_point<std::chrono::steady_clock>,
               static_cast<unsigned>(Events::State::SIZE)>
        counters{};
  public:
    void end(const Events::State event, const std::chrono::time_point<std::chrono::steady_clock> time) noexcept {
      times[static_cast<unsigned>(event)] += std::chrono::steady_clock::now() - time;
    }

    void print() noexcept {
      for (unsigned i = 0; i < static_cast<unsigned>(Events::State::SIZE); i++) {
        std::cerr << Events::as_string[i] << ":" << times[i].count() << "s\n";
      }
      std::cerr << "\n";
    }
  };

  class NoTimer {
  public:
    void end(const Events::State, const std::chrono::time_point<std::chrono::steady_clock>) noexcept {}
    void print() noexcept {}
  };

  template <typename T> class TimeIt {
  public:
    TimeIt(T &timer, Events::State event) noexcept 
      : timer_{timer}, val_{std::chrono::steady_clock::now()}, event_{event} {}

    ~TimeIt() noexcept {
      timer_.end(event_, val_);
    }

  private:
    T &timer_;
    std::chrono::time_point<std::chrono::steady_clock> val_;
    Events::State event_;
  };

  using TimerType = ActiveTimer;
}

#endif

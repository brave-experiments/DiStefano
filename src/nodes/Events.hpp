#ifndef INCLUDED_EVENTS_HPP
#define INCLUDED_EVENTS_HPP
#include <array>
#include <cstdint>

/**
   Events. This namespace contains certain events that we want to track from
either a bandwidth or time tracking perspective. These are essentially a 1:1
mapping between events here and states in ServerState, but these are
deliberately decoupled.
**/
namespace Events {
/**
 State. This enum contains certain events that we want to track from either a
bandwidth or time tracking perspective. These are essentially a 1:1 mapping
between events here and states in ServerState, but these are deliberately
decoupled.
**/
enum class State : uint8_t {
  ACCEPT = 0,
  HANDSHAKE = 1,
  HANDSHAKE_DONE = 2,
  READING_KS = 3,
  MAKING_KS = 4,
  WRITING_KS = 5,
  READING_SKS = 6,
  FINISHING_TPH = 7,
  WRITING_HS_RECV = 8,
  ECTF_WAIT = 9,
  ECTF_DONE = 10,
  KS_WAIT = 11,
  KS_DONE = 12,
  CIRCUIT_PREPROC = 13,
  CERT_WAIT = 14,
  CERT_WRITE = 15,
  DERIVE_TS = 16,
  DERIVE_GCM_SHARES = 17,
  SIZE = 18,
};

inline static constexpr std::array<const char *,
                                   static_cast<unsigned>(State::SIZE)>
    as_string{
        "ACCEPT",      "HANDSHAKE",       "HANDSHAKE_DONE",
        "READING_KS",  "MAKING_KS",       "WRITING_KS",
        "READING_SKS", "FINISHING_TPH",   "WRITING_HS_RECV",
        "ECTF_WAIT",   "ECTF_DONE",       "KS_WAIT",
        "KS_DONE",     "CIRCUIT_PREPROC", "CERT_WAIT",
        "CERT_WRITE",  "DERIVE_TS",       "DERIVE_GCM_SHARES",
    };
} // namespace Events
#endif

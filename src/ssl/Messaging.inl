#ifndef INCLUDED_MESSAGING_HPP
#error Do not include Messaging.inl without Messaging.hpp
#endif

constexpr bool Messaging::is_valid_header(const std::uint8_t header) noexcept {
  return header < static_cast<std::uint8_t>(Messaging::MessageHeaders::SIZE);
}

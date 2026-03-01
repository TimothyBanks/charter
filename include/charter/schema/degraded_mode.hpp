#pragma once

#include <charter/schema/enum_string.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace charter::schema {

enum class degraded_mode_t : uint8_t {
  normal = 0,
  read_only = 1,
  emergency_halt = 2,
};

inline constexpr auto kDegradedModeMappings = std::array{
    std::pair<std::string_view, degraded_mode_t>{"normal",
                                                 degraded_mode_t::normal},
    std::pair<std::string_view, degraded_mode_t>{"read_only",
                                                 degraded_mode_t::read_only},
    std::pair<std::string_view, degraded_mode_t>{
        "emergency_halt", degraded_mode_t::emergency_halt},
};

template <>
inline std::optional<degraded_mode_t> try_from_string<degraded_mode_t>(
    const std::string_view value) {
  return from_string(value, kDegradedModeMappings);
}

inline constexpr std::string_view to_string(const degraded_mode_t value) {
  return to_string(value, kDegradedModeMappings).value_or("unknown");
}

}  // namespace charter::schema

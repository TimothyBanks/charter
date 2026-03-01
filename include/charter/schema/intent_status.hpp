#pragma once

#include <charter/schema/enum_string.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

// Schema type: intent status.
// Custody workflow: Intent lifecycle enum: proposed, approved, executed,
// cancelled, expired-style states.
namespace charter::schema {

enum class intent_status_t : uint8_t {
  proposed = 0,
  pending_approval = 1,
  executable = 2,
  executed = 3,
  cancelled = 4,
  expired = 5
};

inline constexpr auto kIntentStatusMappings =
    std::array{std::pair<std::string_view, intent_status_t>{
                   "proposed", intent_status_t::proposed},
               std::pair<std::string_view, intent_status_t>{
                   "pending_approval", intent_status_t::pending_approval},
               std::pair<std::string_view, intent_status_t>{
                   "executable", intent_status_t::executable},
               std::pair<std::string_view, intent_status_t>{
                   "executed", intent_status_t::executed},
               std::pair<std::string_view, intent_status_t>{
                   "cancelled", intent_status_t::cancelled},
               std::pair<std::string_view, intent_status_t>{
                   "expired", intent_status_t::expired}};

template <>
inline std::optional<intent_status_t> try_from_string<intent_status_t>(
    const std::string_view value) {
  return from_string(value, kIntentStatusMappings);
}

inline constexpr std::string_view to_string(const intent_status_t value) {
  return to_string(value, kIntentStatusMappings).value_or("unknown");
}

}  // namespace charter::schema

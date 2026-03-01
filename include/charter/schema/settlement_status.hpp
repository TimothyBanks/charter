#pragma once

#include <charter/schema/enum_string.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

// Schema type: settlement status.
// Custody workflow: Tracks external chain settlement progression independently
// from intent policy lifecycle status.
namespace charter::schema {

enum class settlement_status_t : uint8_t {
  none = 0,
  authorized = 1,
  submitted = 2,
  confirmed = 3,
  failed = 4,
  expired = 5,
};

inline constexpr auto kSettlementStatusMappings = std::array{
    std::pair<std::string_view, settlement_status_t>{"none",
                                                     settlement_status_t::none},
    std::pair<std::string_view, settlement_status_t>{
        "authorized", settlement_status_t::authorized},
    std::pair<std::string_view, settlement_status_t>{
        "submitted", settlement_status_t::submitted},
    std::pair<std::string_view, settlement_status_t>{
        "confirmed", settlement_status_t::confirmed},
    std::pair<std::string_view, settlement_status_t>{
        "failed", settlement_status_t::failed},
    std::pair<std::string_view, settlement_status_t>{
        "expired", settlement_status_t::expired},
};

template <>
inline std::optional<settlement_status_t> try_from_string<settlement_status_t>(
    const std::string_view value) {
  return from_string(value, kSettlementStatusMappings);
}

inline constexpr std::string_view to_string(const settlement_status_t value) {
  return to_string(value, kSettlementStatusMappings).value_or("unknown");
}

}  // namespace charter::schema

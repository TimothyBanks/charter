#pragma once

#include <charter/schema/enum_string.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

// Schema type: settlement authority mode.
// Custody workflow: Defines who signs/submits the origin-chain settlement
// transaction after Charter policy checks pass.
namespace charter::schema {

enum class settlement_authority_mode_t : uint8_t {
  custodian_signed = 0,
  client_signed = 1,
};

inline constexpr auto kSettlementAuthorityModeMappings = std::array{
    std::pair<std::string_view, settlement_authority_mode_t>{
        "custodian_signed", settlement_authority_mode_t::custodian_signed},
    std::pair<std::string_view, settlement_authority_mode_t>{
        "client_signed", settlement_authority_mode_t::client_signed},
};

template <>
inline std::optional<settlement_authority_mode_t>
try_from_string<settlement_authority_mode_t>(const std::string_view value) {
  return from_string(value, kSettlementAuthorityModeMappings);
}

inline constexpr std::string_view to_string(
    const settlement_authority_mode_t value) {
  return to_string(value, kSettlementAuthorityModeMappings).value_or("unknown");
}

}  // namespace charter::schema

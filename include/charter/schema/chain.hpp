#pragma once

#include <array>
#include <charter/schema/enum_string.hpp>
#include <charter/schema/primitives.hpp>
#include <cstdint>
#include <optional>
#include <string_view>
#include <variant>

// Schema type: chain.
// Custody workflow: Settlement chain identifier: normalized chain type used in
// asset/address semantics.
namespace charter::schema {

enum class chain_type : uint16_t {
  bitcoin = 0,
  ethereum = 1,
  solana = 2,
  eosio = 3,
};

inline constexpr auto kChainTypeMappings = std::array{
    std::pair<std::string_view, chain_type>{"bitcoin", chain_type::bitcoin},
    std::pair<std::string_view, chain_type>{"ethereum", chain_type::ethereum},
    std::pair<std::string_view, chain_type>{"solana", chain_type::solana},
    std::pair<std::string_view, chain_type>{"eosio", chain_type::eosio},
};

template <>
inline std::optional<chain_type> try_from_string<chain_type>(
    const std::string_view value) {
  return from_string(value, kChainTypeMappings);
}

inline constexpr std::string_view to_string(const chain_type value) {
  return to_string(value, kChainTypeMappings).value_or("unknown");
}

// bytes - user defined identifier
using chain_type_t = std::variant<chain_type, bytes_t>;

}  // namespace charter::schema

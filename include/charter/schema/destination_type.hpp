#pragma once

#include <charter/schema/enum_string.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

// Schema type: destination type.
// Custody workflow: Destination classification enum: address vs contract
// semantics for destination controls.
namespace charter::schema {

enum class destination_type_t : uint8_t { address = 0, contract = 1 };

inline constexpr auto kDestinationTypeMappings = std::array{
    std::pair<std::string_view, destination_type_t>{
        "address", destination_type_t::address},
    std::pair<std::string_view, destination_type_t>{
        "contract", destination_type_t::contract},
};

template <>
inline std::optional<destination_type_t> try_from_string<destination_type_t>(
    const std::string_view value) {
  return from_string(value, kDestinationTypeMappings);
}

inline constexpr std::string_view to_string(const destination_type_t value) {
  return to_string(value, kDestinationTypeMappings).value_or("unknown");
}

}  // namespace charter::schema

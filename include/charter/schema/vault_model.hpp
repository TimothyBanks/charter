#pragma once

#include <charter/schema/enum_string.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

// Schema type: vault model.
// Custody workflow: Custody account model enum: segregated vs omnibus vault
// operation style.
namespace charter::schema {

enum class vault_model_t : uint8_t { segregated = 0, omnibus = 1 };

inline constexpr auto kVaultModelMappings = std::array{
    std::pair<std::string_view, vault_model_t>{"segregated",
                                               vault_model_t::segregated},
    std::pair<std::string_view, vault_model_t>{"omnibus",
                                               vault_model_t::omnibus},
};

template <>
inline std::optional<vault_model_t> try_from_string<vault_model_t>(
    const std::string_view value) {
  return from_string(value, kVaultModelMappings);
}

inline constexpr std::string_view to_string(const vault_model_t value) {
  return to_string(value, kVaultModelMappings).value_or("unknown");
}

}  // namespace charter::schema

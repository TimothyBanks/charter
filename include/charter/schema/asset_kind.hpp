#pragma once

#include <charter/schema/enum_string.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace charter::schema {

enum class asset_kind_t : uint8_t {
  native = 0,
  erc20 = 1,
  erc721 = 2,
  erc1115 = 3,
  other = 4
};

inline constexpr auto kAssetKindMappings = std::array{
    std::pair<std::string_view, asset_kind_t>{"native", asset_kind_t::native},
    std::pair<std::string_view, asset_kind_t>{"erc20", asset_kind_t::erc20},
    std::pair<std::string_view, asset_kind_t>{"erc721", asset_kind_t::erc721},
    std::pair<std::string_view, asset_kind_t>{"erc1115", asset_kind_t::erc1115},
    std::pair<std::string_view, asset_kind_t>{"other", asset_kind_t::other},
};

template <>
inline std::optional<asset_kind_t> try_from_string<asset_kind_t>(
    const std::string_view value) {
  return from_string(value, kAssetKindMappings);
}

inline constexpr std::string_view to_string(const asset_kind_t value) {
  return to_string(value, kAssetKindMappings).value_or("unknown");
}

}  // namespace charter::schema

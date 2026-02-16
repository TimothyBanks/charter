#pragma once
#include <charter/schema/primitives.hpp>

namespace charter::schema {

template <uint16_t Version>
struct disable_asset;

template <>
struct disable_asset<1> final {
  uint16_t version{1};
  hash32_t asset_id;
};

using disable_asset_t = disable_asset<1>;

}  // namespace charter::schema
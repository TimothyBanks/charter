#pragma once
#include <charter/schema/asset_kind.hpp>
#include <charter/schema/asset_ref.hpp>
#include <charter/schema/chain.hpp>
#include <charter/schema/primitives.hpp>

namespace charter::schema {

template <uint16_t Version>
struct asset_state;

template <>
struct asset_state<1> final {
  uint16_t version{1};
  hash32_t asset_id;
  chain_type_t chain;
  asset_kind_t kind;
  asset_ref_t reference;
  std::optional<bytes_t> symbol;
  std::optional<bytes_t> name;
  uint8_t decimals;
  bool enabled;
};

using asset_state_t = asset_state<1>;
using upsert_asset_t = asset_state<1>;

}  // namespace charter::schema
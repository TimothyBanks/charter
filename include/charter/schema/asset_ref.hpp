#pragma once
#include <charter/schema/primitives.hpp>

namespace charter::schema {

template <uint16_t Version>
struct asset_ref_native_symbol;

template <>
struct asset_ref_native_symbol<1> final {
  uint16_t version{1};
  bytes_t symbol;
};

using asset_ref_native_symbol_t = asset_ref_native_symbol<1>;

template <uint16_t Version>
struct asset_ref_contract_address;

template <>
struct asset_ref_contract_address<1> final {
  uint16_t version{1};
  bytes_t address;
};

using asset_ref_contract_address_t = asset_ref_contract_address<1>;

template <uint16_t Version>
struct asset_ref_composite;

template <>
struct asset_ref_composite<1> final {
  uint16_t version{1};
  std::vector<bytes_t> parts;
};

using asset_ref_composite_t = asset_ref_composite<1>;

using asset_ref_t = std::variant<asset_ref_native_symbol_t,
                                 asset_ref_contract_address_t,
                                 asset_ref_composite_t>;

}  // namespace charter::schema
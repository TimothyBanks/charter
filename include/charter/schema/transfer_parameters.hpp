#pragma once
#include <charter/schema/primitives.hpp>

namespace charter::schema {

template <uint16_t Version>
struct transfer_parameters;

template <>
struct transfer_parameters<1> final {
  uint16_t version{1};
  hash32_t asset_id;
};

using transfer_parameters_t = transfer_parameters<1>;
}  // namespace charter::schema
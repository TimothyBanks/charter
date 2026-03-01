#pragma once
#include <charter/schema/primitives.hpp>

// Schema type: transfer parameters.
// Custody workflow: Transfer action payload: asset and amount details for value
// movement intents.
namespace charter::schema {

template <uint16_t Version>
struct transfer_parameters;

template <>
struct transfer_parameters<1> final {
  uint16_t version{1};
  hash32_t asset_id;
  hash32_t destination_id;
  uint64_t amount{};
};

using transfer_parameters_t = transfer_parameters<1>;
}  // namespace charter::schema

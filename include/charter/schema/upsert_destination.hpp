#pragma once
#include <charter/schema/chain.hpp>
#include <charter/schema/destination_type.hpp>
#include <charter/schema/primitives.hpp>
#include <optional>

namespace charter::schema {

template <uint16_t Version>
struct upsert_destination;

template <>
struct upsert_destination<1> final {
  uint16_t version{1};
  hash32_t workspace_id;
  hash32_t destination_id;  // can be derived from (chain, type, address)
  destination_type_t type;
  chain_type_t chain_type;
  bytes_t address_or_contract;  // must be canonical per chain (user defines)
  bool enabled{false};
  std::optional<bytes_t> label;
};

using upsert_destination_t = upsert_destination<1>;
using destination_state_t = upsert_destination<1>;

}  // namespace charter::schema
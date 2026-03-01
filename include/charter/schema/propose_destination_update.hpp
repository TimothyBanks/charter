#pragma once

#include <charter/schema/chain.hpp>
#include <charter/schema/destination_type.hpp>
#include <charter/schema/primitives.hpp>
#include <optional>

// Schema type: propose destination update.
// Custody workflow: Destination change request: proposes a controlled update to
// an existing destination configuration.
namespace charter::schema {

template <uint16_t Version>
struct propose_destination_update;

template <>
struct propose_destination_update<1> final {
  uint16_t version{1};
  hash32_t workspace_id;
  hash32_t destination_id;
  hash32_t update_id;
  destination_type_t type;
  chain_type_t chain_type;
  bytes_t address_or_contract;
  bool enabled{false};
  std::optional<bytes_t> label;
  uint32_t required_approvals{1};
  uint64_t delay_ms{};
};

using propose_destination_update_t = propose_destination_update<1>;

}  // namespace charter::schema

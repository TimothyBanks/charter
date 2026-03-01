#pragma once

#include <charter/schema/chain.hpp>
#include <charter/schema/destination_type.hpp>
#include <charter/schema/destination_update_status.hpp>
#include <charter/schema/primitives.hpp>
#include <optional>

// Schema type: destination update state.
// Custody workflow: Destination change-management state: tracks pending and
// approved destination updates.
namespace charter::schema {

template <uint16_t Version>
struct destination_update_state;

template <>
struct destination_update_state<1> final {
  uint16_t version{1};
  hash32_t workspace_id;
  hash32_t destination_id;
  hash32_t update_id;
  destination_type_t type;
  chain_type_t chain_type;
  bytes_t address_or_contract;
  bool enabled{false};
  std::optional<bytes_t> label;
  signer_id_t created_by;
  timestamp_milliseconds_t created_at{};
  timestamp_milliseconds_t not_before{};
  uint32_t required_approvals{1};
  uint32_t approvals_count{};
  destination_update_status_t status{
      destination_update_status_t::pending_approval};
};

using destination_update_state_t = destination_update_state<1>;

}  // namespace charter::schema

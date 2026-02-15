#pragma once
#include <charter/schema/claim_requirement.hpp>
#include <charter/schema/intent_action.hpp>
#include <charter/schema/intent_status.hpp>
#include <charter/schema/primitives.hpp>
#include <vector>

namespace charter::schema {

template <uint16_t Version> struct intent_state;

template <> struct intent_state<1> final {
  hash32_t workspace_id;
  hash32_t vault_id;
  hash32_t intent_id;
  signer_id_t created_by;
  timestamp_milliseconds_t create_at;
  timestamp_milliseconds_t not_before;
  std::optional<timestamp_milliseconds_t> expires_at;
  intent_action_t action;
  intent_status_t status;
  hash32_t policy_set_id;
  uint32_t policy_version;
  uint32_t required_threshold;
  uint32_t approvals_count;
  std::vector<claim_requirement_t> claim_requirements;
};

using intent_state_t = intent_state<1>;

} // namespace charter::schema
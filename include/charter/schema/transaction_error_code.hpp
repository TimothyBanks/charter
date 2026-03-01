#pragma once

#include <cstdint>

namespace charter::schema {

enum class transaction_error_code : uint32_t {
  invalid_transaction = 1,
  unsupported_transaction_version = 2,
  invalid_chain_id = 3,
  invalid_nonce = 4,
  invalid_signature_type = 5,
  signature_verification_failed = 6,
  workspace_exists = 10,
  workspace_missing = 11,
  vault_exists = 12,
  policy_scope_missing = 13,
  policy_set_exists = 14,
  policy_set_missing = 15,
  vault_scope_missing = 16,
  active_policy_missing = 17,
  workspace_missing_for_operation = 18,
  intent_exists = 19,
  policy_resolution_failed = 20,
  intent_missing = 21,
  intent_not_approvable = 22,
  intent_expired = 23,
  duplicate_approval = 24,
  intent_already_executed = 25,
  intent_not_executable = 26,
  attestation_missing = 27,
  limit_exceeded = 28,
  destination_not_whitelisted = 29,
  claim_requirement_unsatisfied = 30,
  signer_quarantined = 31,
  degraded_mode_active = 32,
  authorization_denied = 33,
  velocity_limit_exceeded = 34,
  separation_of_duties_violated = 35,
  destination_update_exists = 36,
  destination_update_missing = 37,
  destination_update_finalized = 38,
  destination_update_not_executable = 39,
  asset_missing = 40,
  asset_disabled = 41,
  jurisdiction_mismatch = 42,
};

}  // namespace charter::schema

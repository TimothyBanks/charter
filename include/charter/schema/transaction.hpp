#pragma once
#include <charter/schema/activate_policy_set.hpp>
#include <charter/schema/apply_destination_update.hpp>
#include <charter/schema/approve_destination_update.hpp>
#include <charter/schema/approve_intent.hpp>
#include <charter/schema/asset_state.hpp>
#include <charter/schema/cancel_intent.hpp>
#include <charter/schema/create_policy_set.hpp>
#include <charter/schema/create_vault.hpp>
#include <charter/schema/create_workspace.hpp>
#include <charter/schema/disable_asset.hpp>
#include <charter/schema/execute_intent.hpp>
#include <charter/schema/primitives.hpp>
#include <charter/schema/propose_destination_update.hpp>
#include <charter/schema/propose_intent.hpp>
#include <charter/schema/revoke_attestation.hpp>
#include <charter/schema/set_degraded_mode.hpp>
#include <charter/schema/upsert_attestation.hpp>
#include <charter/schema/upsert_destination.hpp>
#include <charter/schema/upsert_role_assignment.hpp>
#include <charter/schema/upsert_signer_quarantine.hpp>
#include <variant>

namespace charter::schema {

using transaction_payload_t = std::variant<activate_policy_set_t,
                                           apply_destination_update_t,
                                           approve_destination_update_t,
                                           approve_intent_t,
                                           cancel_intent_t,
                                           create_policy_set_t,
                                           create_workspace_t,
                                           create_vault_t,
                                           execute_intent_t,
                                           propose_destination_update_t,
                                           propose_intent_t,
                                           revoke_attestation_t,
                                           set_degraded_mode_t,
                                           upsert_attestation_t,
                                           upsert_destination_t,
                                           upsert_role_assignment_t,
                                           upsert_signer_quarantine_t,
                                           disable_asset_t,
                                           upsert_asset_t>;

template <uint16_t Version>
struct transaction;

template <>
struct transaction<1> final {
  uint16_t version{1};
  hash32_t chain_id{};
  uint64_t nonce{};
  signer_id_t signer{};
  transaction_payload_t payload{};
  signature_t signature;
};

using transaction_t = transaction<1>;

}  // namespace charter::schema

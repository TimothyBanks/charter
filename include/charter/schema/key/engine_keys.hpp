#pragma once

#include <array>
#include <charter/schema/claim_type.hpp>
#include <charter/schema/primitives.hpp>
#include <charter/schema/role_id.hpp>
#include <charter/schema/velocity_window.hpp>
#include <cstdint>
#include <optional>
#include <string_view>
#include <utility>

namespace charter::schema::key {

extern const std::string_view kNonceKeyPrefix;
extern const std::string_view kStatePrefix;
extern const std::string_view kWorkspaceKeyPrefix;
extern const std::string_view kVaultKeyPrefix;
extern const std::string_view kDestinationKeyPrefix;
extern const std::string_view kPolicySetKeyPrefix;
extern const std::string_view kActivePolicyPrefix;
extern const std::string_view kIntentKeyPrefix;
extern const std::string_view kApprovalKeyPrefix;
extern const std::string_view kDestinationUpdateKeyPrefix;
extern const std::string_view kAttestationKeyPrefix;
extern const std::string_view kRoleAssignmentKeyPrefix;
extern const std::string_view kSignerQuarantineKeyPrefix;
extern const std::string_view kDegradedModeKeyPrefix;
extern const std::string_view kEventSeqKeyPrefix;
extern const std::string_view kVelocityKeyPrefix;
extern const std::string_view kHistoryPrefix;
extern const std::string_view kEventPrefix;
extern const std::string_view kSnapshotPrefix;

extern const std::array<std::string_view, 19> kEngineKeyspaces;

charter::schema::bytes_t make_prefixed_key(std::string_view prefix,
                                           const charter::schema::bytes_t& id);
charter::schema::bytes_t make_workspace_key(
    const charter::schema::hash32_t& workspace_id);
charter::schema::bytes_t make_vault_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id);
charter::schema::bytes_t make_destination_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& destination_id);
charter::schema::bytes_t make_nonce_key(
    const charter::schema::signer_id_t& signer);
charter::schema::bytes_t make_policy_set_key(
    const charter::schema::hash32_t& policy_set_id,
    uint32_t policy_version);
charter::schema::bytes_t make_active_policy_key(
    const charter::schema::policy_scope_t& scope);
charter::schema::bytes_t make_intent_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id,
    const charter::schema::hash32_t& intent_id);
charter::schema::bytes_t make_approval_key(
    const charter::schema::hash32_t& intent_id,
    const charter::schema::signer_id_t& signer);
charter::schema::bytes_t make_destination_update_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& destination_id,
    const charter::schema::hash32_t& update_id);
charter::schema::bytes_t make_attestation_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& subject,
    const charter::schema::claim_type_t& claim,
    const charter::schema::signer_id_t& issuer);
charter::schema::bytes_t make_attestation_prefix_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& subject,
    const charter::schema::claim_type_t& claim);
charter::schema::bytes_t make_role_assignment_key(
    const charter::schema::policy_scope_t& scope,
    const charter::schema::signer_id_t& subject,
    charter::schema::role_id_t role);
charter::schema::bytes_t make_signer_quarantine_key(
    const charter::schema::signer_id_t& signer);
charter::schema::bytes_t make_degraded_mode_key();
charter::schema::bytes_t make_event_sequence_key();
charter::schema::bytes_t make_history_key(uint64_t height, uint32_t index);
charter::schema::bytes_t make_event_key(uint64_t event_id);
charter::schema::bytes_t make_velocity_counter_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id,
    const std::optional<charter::schema::asset_id_t>& asset_id,
    charter::schema::velocity_window_t window,
    uint64_t window_start_ms);
std::optional<std::pair<uint64_t, uint32_t>> parse_history_key(
    const charter::schema::bytes_view_t& key);
std::optional<uint64_t> parse_event_key(
    const charter::schema::bytes_view_t& key);

}  // namespace charter::schema::key

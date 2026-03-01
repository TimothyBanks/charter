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

// Schema key type: engine keys.
// Custody workflow: Defines canonical key prefixes and key codecs for custody
// state, history, snapshots, and events.
namespace charter::schema::key {

inline constexpr std::string_view kNonceKeyPrefix{"SYS|STATE|NONCE|"};
inline constexpr std::string_view kStatePrefix{"SYS|STATE|"};
inline constexpr std::string_view kWorkspaceKeyPrefix{"SYS|STATE|WORKSPACE|"};
inline constexpr std::string_view kVaultKeyPrefix{"SYS|STATE|VAULT|"};
inline constexpr std::string_view kAssetKeyPrefix{"SYS|STATE|ASSET|"};
inline constexpr std::string_view kDestinationKeyPrefix{
    "SYS|STATE|DESTINATION|"};
inline constexpr std::string_view kPolicySetKeyPrefix{"SYS|STATE|POLICY_SET|"};
inline constexpr std::string_view kActivePolicyPrefix{
    "SYS|STATE|ACTIVE_POLICY|"};
inline constexpr std::string_view kIntentKeyPrefix{"SYS|STATE|INTENT|"};
inline constexpr std::string_view kApprovalKeyPrefix{"SYS|STATE|APPROVAL|"};
inline constexpr std::string_view kDestinationUpdateKeyPrefix{
    "SYS|STATE|DESTINATION_UPDATE|"};
inline constexpr std::string_view kAttestationKeyPrefix{"SYS|STATE|ATTEST|"};
inline constexpr std::string_view kRoleAssignmentKeyPrefix{
    "SYS|STATE|ROLE_ASSIGNMENT|"};
inline constexpr std::string_view kSignerQuarantineKeyPrefix{
    "SYS|STATE|SIGNER_QUARANTINE|"};
inline constexpr std::string_view kDegradedModeKeyPrefix{
    "SYS|STATE|DEGRADED_MODE|"};
inline constexpr std::string_view kEventSeqKeyPrefix{"SYS|STATE|EVENT_SEQ|"};
inline constexpr std::string_view kVelocityKeyPrefix{"SYS|STATE|VELOCITY|"};
inline constexpr std::string_view kHistoryPrefix{"SYS|HISTORY|TX|"};
inline constexpr std::string_view kEventPrefix{"SYS|EVENT|"};
inline constexpr std::string_view kSnapshotPrefix{"SYS|SNAP|"};

inline const std::array<std::string_view, 20> kEngineKeyspaces{
    kNonceKeyPrefix,
    kStatePrefix,
    kWorkspaceKeyPrefix,
    kVaultKeyPrefix,
    kAssetKeyPrefix,
    kDestinationKeyPrefix,
    kPolicySetKeyPrefix,
    kActivePolicyPrefix,
    kIntentKeyPrefix,
    kApprovalKeyPrefix,
    kDestinationUpdateKeyPrefix,
    kAttestationKeyPrefix,
    kRoleAssignmentKeyPrefix,
    kSignerQuarantineKeyPrefix,
    kDegradedModeKeyPrefix,
    kEventSeqKeyPrefix,
    kVelocityKeyPrefix,
    kHistoryPrefix,
    kEventPrefix,
    kSnapshotPrefix};

template <typename Encoder>
charter::schema::bytes_t make_signer_cache_key(
    Encoder& encoder,
    const charter::schema::signer_id_t& signer) {
  return encoder.encode(signer);
}

template <typename Encoder, typename T>
charter::schema::bytes_t make_prefixed_key(Encoder& encoder,
                                           std::string_view prefix,
                                           const T& id) {
  // SCALE product types are encoded as concatenated field bytes.
  // This is equivalent to encoding tuple{prefix, id}.
  auto key = encoder.encode(prefix);
  encoder.encode(id, key);
  return key;
}

template <typename Encoder>
charter::schema::bytes_t make_prefix_key(Encoder& encoder,
                                         std::string_view prefix) {
  return encoder.encode(prefix);
}

template <typename Encoder>
charter::schema::bytes_t make_workspace_key(
    Encoder& encoder,
    const charter::schema::hash32_t& workspace_id) {
  auto workspace_bytes = charter::schema::bytes_t{};
  workspace_bytes.reserve(workspace_id.size());
  workspace_bytes.insert(std::end(workspace_bytes), std::begin(workspace_id),
                         std::end(workspace_id));
  return make_prefixed_key(encoder, kWorkspaceKeyPrefix, workspace_bytes);
}

template <typename Encoder>
charter::schema::bytes_t make_vault_key(
    Encoder& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id) {
  return make_prefixed_key(encoder, kVaultKeyPrefix,
                           std::tuple{workspace_id, vault_id});
}

template <typename Encoder>
charter::schema::bytes_t make_asset_key(
    Encoder& encoder,
    const charter::schema::hash32_t& asset_id) {
  return make_prefixed_key(encoder, kAssetKeyPrefix, asset_id);
}

template <typename Encoder>
charter::schema::bytes_t make_destination_key(
    Encoder& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& destination_id) {
  return make_prefixed_key(encoder, kDestinationKeyPrefix,
                           std::tuple{workspace_id, destination_id});
}

template <typename Encoder>
charter::schema::bytes_t make_nonce_key(
    Encoder& encoder,
    const charter::schema::signer_id_t& signer) {
  return make_prefixed_key(encoder, kNonceKeyPrefix, signer);
}

template <typename Encoder>
charter::schema::bytes_t make_policy_set_key(
    Encoder& encoder,
    const charter::schema::hash32_t& policy_set_id,
    uint32_t policy_version) {
  return make_prefixed_key(encoder, kPolicySetKeyPrefix,
                           std::tuple{policy_set_id, policy_version});
}

template <typename Encoder>
charter::schema::bytes_t make_active_policy_key(
    Encoder& encoder,
    const charter::schema::policy_scope_t& scope) {
  return make_prefixed_key(encoder, kActivePolicyPrefix, scope);
}

template <typename Encoder>
charter::schema::bytes_t make_intent_key(
    Encoder& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id,
    const charter::schema::hash32_t& intent_id) {
  return make_prefixed_key(encoder, kIntentKeyPrefix,
                           std::tuple{workspace_id, vault_id, intent_id});
}

template <typename Encoder>
charter::schema::bytes_t make_approval_key(
    Encoder& encoder,
    const charter::schema::hash32_t& intent_id,
    const charter::schema::signer_id_t& signer) {
  return make_prefixed_key(encoder, kApprovalKeyPrefix,
                           std::tuple{intent_id, signer});
}

template <typename Encoder>
charter::schema::bytes_t make_destination_update_key(
    Encoder& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& destination_id,
    const charter::schema::hash32_t& update_id) {
  return make_prefixed_key(encoder, kDestinationUpdateKeyPrefix,
                           std::tuple{workspace_id, destination_id, update_id});
}

template <typename Encoder>
charter::schema::bytes_t make_attestation_key(
    Encoder& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& subject,
    const charter::schema::claim_type_t& claim,
    const charter::schema::signer_id_t& issuer) {
  return make_prefixed_key(encoder, kAttestationKeyPrefix,
                           std::tuple{workspace_id, subject, claim, issuer});
}

template <typename Encoder>
charter::schema::bytes_t make_attestation_prefix_key(
    Encoder& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& subject,
    const charter::schema::claim_type_t& claim) {
  return make_prefixed_key(encoder, kAttestationKeyPrefix,
                           std::tuple{workspace_id, subject, claim});
}

template <typename Encoder>
charter::schema::bytes_t make_role_assignment_key(
    Encoder& encoder,
    const charter::schema::policy_scope_t& scope,
    const charter::schema::signer_id_t& subject,
    const charter::schema::role_id_t role) {
  return make_prefixed_key(encoder, kRoleAssignmentKeyPrefix,
                           std::tuple{scope, subject, role});
}

template <typename Encoder>
charter::schema::bytes_t make_signer_quarantine_key(
    Encoder& encoder,
    const charter::schema::signer_id_t& signer) {
  return make_prefixed_key(encoder, kSignerQuarantineKeyPrefix, signer);
}

template <typename Encoder>
charter::schema::bytes_t make_degraded_mode_key(Encoder& encoder) {
  return make_prefixed_key(encoder, kDegradedModeKeyPrefix,
                           std::string_view{"CURRENT"});
}

template <typename Encoder>
charter::schema::bytes_t make_event_sequence_key(Encoder& encoder) {
  return make_prefixed_key(encoder, kEventSeqKeyPrefix,
                           std::string_view{"NEXT"});
}

template <typename Encoder>
charter::schema::bytes_t make_history_key(Encoder& encoder,
                                          uint64_t height,
                                          uint32_t index) {
  return make_prefixed_key(encoder, kHistoryPrefix, std::tuple{height, index});
}

template <typename Encoder>
charter::schema::bytes_t make_event_key(Encoder& encoder, uint64_t event_id) {
  return make_prefixed_key(encoder, kEventPrefix, event_id);
}

template <typename Encoder>
charter::schema::bytes_t make_velocity_counter_key(
    Encoder& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id,
    const std::optional<charter::schema::asset_id_t>& asset_id,
    const charter::schema::velocity_window_t window,
    uint64_t window_start_ms) {
  return make_prefixed_key(
      encoder, kVelocityKeyPrefix,
      std::tuple{workspace_id, vault_id, asset_id, window, window_start_ms});
}

template <typename Encoder>
std::optional<std::pair<uint64_t, uint32_t>> parse_history_key(
    Encoder& encoder,
    const charter::schema::bytes_view_t& key) {
  auto decoded = encoder.template try_decode<
      std::tuple<std::string, std::tuple<uint64_t, uint32_t>>>(key);
  if (!decoded.has_value()) {
    return std::nullopt;
  }
  if (std::get<0>(decoded.value()) != kHistoryPrefix) {
    return std::nullopt;
  }
  return std::pair<uint64_t, uint32_t>{
      std::get<0>(std::get<1>(decoded.value())),
      std::get<1>(std::get<1>(decoded.value()))};
}

template <typename Encoder>
std::optional<uint64_t> parse_event_key(
    Encoder& encoder,
    const charter::schema::bytes_view_t& key) {
  auto decoded =
      encoder.template try_decode<std::tuple<std::string, uint64_t>>(key);
  if (!decoded.has_value()) {
    return std::nullopt;
  }
  if (std::get<0>(decoded.value()) != kEventPrefix) {
    return std::nullopt;
  }
  return std::get<1>(decoded.value());
}

}  // namespace charter::schema::key

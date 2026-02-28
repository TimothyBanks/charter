#include <charter/schema/key/engine_keys.hpp>

#include <charter/schema/encoding/scale/encoder.hpp>

#include <tuple>

namespace charter::schema::key {

namespace {

using key_encoder_t = charter::schema::encoding::encoder<
    charter::schema::encoding::scale_encoder_tag>;

}  // namespace

const std::string_view kNonceKeyPrefix{"SYS|STATE|NONCE|"};
const std::string_view kStatePrefix{"SYS|STATE|"};
const std::string_view kWorkspaceKeyPrefix{"SYS|STATE|WORKSPACE|"};
const std::string_view kVaultKeyPrefix{"SYS|STATE|VAULT|"};
const std::string_view kDestinationKeyPrefix{"SYS|STATE|DESTINATION|"};
const std::string_view kPolicySetKeyPrefix{"SYS|STATE|POLICY_SET|"};
const std::string_view kActivePolicyPrefix{"SYS|STATE|ACTIVE_POLICY|"};
const std::string_view kIntentKeyPrefix{"SYS|STATE|INTENT|"};
const std::string_view kApprovalKeyPrefix{"SYS|STATE|APPROVAL|"};
const std::string_view kDestinationUpdateKeyPrefix{
    "SYS|STATE|DESTINATION_UPDATE|"};
const std::string_view kAttestationKeyPrefix{"SYS|STATE|ATTEST|"};
const std::string_view kRoleAssignmentKeyPrefix{"SYS|STATE|ROLE_ASSIGNMENT|"};
const std::string_view kSignerQuarantineKeyPrefix{
    "SYS|STATE|SIGNER_QUARANTINE|"};
const std::string_view kDegradedModeKeyPrefix{"SYS|STATE|DEGRADED_MODE|"};
const std::string_view kEventSeqKeyPrefix{"SYS|STATE|EVENT_SEQ|"};
const std::string_view kVelocityKeyPrefix{"SYS|STATE|VELOCITY|"};
const std::string_view kHistoryPrefix{"SYS|HISTORY|TX|"};
const std::string_view kEventPrefix{"SYS|EVENT|"};
const std::string_view kSnapshotPrefix{"SYS|SNAP|"};

const std::array<std::string_view, 19> kEngineKeyspaces{
    kNonceKeyPrefix,
    kStatePrefix,
    kWorkspaceKeyPrefix,
    kVaultKeyPrefix,
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

charter::schema::bytes_t make_prefixed_key(std::string_view prefix,
                                           const charter::schema::bytes_t& id) {
  auto key = charter::schema::make_bytes(prefix);
  key.reserve(key.size() + id.size());
  key.insert(std::end(key), std::begin(id), std::end(id));
  return key;
}

charter::schema::bytes_t make_workspace_key(
    const charter::schema::hash32_t& workspace_id) {
  auto workspace_bytes = charter::schema::bytes_t{};
  workspace_bytes.reserve(workspace_id.size());
  workspace_bytes.insert(std::end(workspace_bytes), std::begin(workspace_id),
                         std::end(workspace_id));
  return make_prefixed_key(kWorkspaceKeyPrefix, workspace_bytes);
}

charter::schema::bytes_t make_vault_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id) {
  return make_prefixed_key(kVaultKeyPrefix, key_encoder_t{}.encode(std::tuple{
                                                workspace_id, vault_id}));
}

charter::schema::bytes_t make_destination_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& destination_id) {
  return make_prefixed_key(
      kDestinationKeyPrefix,
      key_encoder_t{}.encode(std::tuple{workspace_id, destination_id}));
}

charter::schema::bytes_t make_nonce_key(
    const charter::schema::signer_id_t& signer) {
  return make_prefixed_key(kNonceKeyPrefix, key_encoder_t{}.encode(signer));
}

charter::schema::bytes_t make_policy_set_key(
    const charter::schema::hash32_t& policy_set_id,
    uint32_t policy_version) {
  return make_prefixed_key(
      kPolicySetKeyPrefix,
      key_encoder_t{}.encode(std::tuple{policy_set_id, policy_version}));
}

charter::schema::bytes_t make_active_policy_key(
    const charter::schema::policy_scope_t& scope) {
  return make_prefixed_key(kActivePolicyPrefix, key_encoder_t{}.encode(scope));
}

charter::schema::bytes_t make_intent_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id,
    const charter::schema::hash32_t& intent_id) {
  return make_prefixed_key(
      kIntentKeyPrefix,
      key_encoder_t{}.encode(std::tuple{workspace_id, vault_id, intent_id}));
}

charter::schema::bytes_t make_approval_key(
    const charter::schema::hash32_t& intent_id,
    const charter::schema::signer_id_t& signer) {
  return make_prefixed_key(
      kApprovalKeyPrefix,
      key_encoder_t{}.encode(std::tuple{intent_id, signer}));
}

charter::schema::bytes_t make_destination_update_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& destination_id,
    const charter::schema::hash32_t& update_id) {
  return make_prefixed_key(kDestinationUpdateKeyPrefix,
                           key_encoder_t{}.encode(std::tuple{
                               workspace_id, destination_id, update_id}));
}

charter::schema::bytes_t make_attestation_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& subject,
    const charter::schema::claim_type_t& claim,
    const charter::schema::signer_id_t& issuer) {
  return make_prefixed_key(
      kAttestationKeyPrefix,
      key_encoder_t{}.encode(std::tuple{workspace_id, subject, claim, issuer}));
}

charter::schema::bytes_t make_attestation_prefix_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& subject,
    const charter::schema::claim_type_t& claim) {
  return make_prefixed_key(
      kAttestationKeyPrefix,
      key_encoder_t{}.encode(std::tuple{workspace_id, subject, claim}));
}

charter::schema::bytes_t make_role_assignment_key(
    const charter::schema::policy_scope_t& scope,
    const charter::schema::signer_id_t& subject,
    const charter::schema::role_id_t role) {
  return make_prefixed_key(
      kRoleAssignmentKeyPrefix,
      key_encoder_t{}.encode(std::tuple{scope, subject, role}));
}

charter::schema::bytes_t make_signer_quarantine_key(
    const charter::schema::signer_id_t& signer) {
  return make_prefixed_key(kSignerQuarantineKeyPrefix,
                           key_encoder_t{}.encode(signer));
}

charter::schema::bytes_t make_degraded_mode_key() {
  return make_prefixed_key(
      kDegradedModeKeyPrefix,
      charter::schema::make_bytes(std::string_view{"CURRENT"}));
}

charter::schema::bytes_t make_event_sequence_key() {
  return make_prefixed_key(kEventSeqKeyPrefix, charter::schema::make_bytes(
                                                   std::string_view{"NEXT"}));
}

charter::schema::bytes_t make_history_key(uint64_t height, uint32_t index) {
  return make_prefixed_key(kHistoryPrefix,
                           key_encoder_t{}.encode(std::tuple{height, index}));
}

charter::schema::bytes_t make_event_key(uint64_t event_id) {
  return make_prefixed_key(kEventPrefix, key_encoder_t{}.encode(event_id));
}

charter::schema::bytes_t make_velocity_counter_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id,
    const std::optional<charter::schema::asset_id_t>& asset_id,
    const charter::schema::velocity_window_t window,
    uint64_t window_start_ms) {
  return make_prefixed_key(
      kVelocityKeyPrefix,
      key_encoder_t{}.encode(std::tuple{workspace_id, vault_id, asset_id,
                                        window, window_start_ms}));
}

std::optional<std::pair<uint64_t, uint32_t>> parse_history_key(
    const charter::schema::bytes_view_t& key) {
  auto key_view =
      std::string_view{reinterpret_cast<const char*>(key.data()), key.size()};
  if (!key_view.starts_with(kHistoryPrefix)) {
    return std::nullopt;
  }
  auto encoded = charter::schema::bytes_view_t{
      key.data() + kHistoryPrefix.size(), key.size() - kHistoryPrefix.size()};
  auto decoded =
      key_encoder_t{}.try_decode<std::tuple<uint64_t, uint32_t>>(encoded);
  if (!decoded) {
    return std::nullopt;
  }
  return std::pair<uint64_t, uint32_t>{std::get<0>(decoded.value()),
                                       std::get<1>(decoded.value())};
}

std::optional<uint64_t> parse_event_key(
    const charter::schema::bytes_view_t& key) {
  auto key_view =
      std::string_view{reinterpret_cast<const char*>(key.data()), key.size()};
  if (!key_view.starts_with(kEventPrefix)) {
    return std::nullopt;
  }
  auto encoded = charter::schema::bytes_view_t{
      key.data() + kEventPrefix.size(), key.size() - kEventPrefix.size()};
  return key_encoder_t{}.try_decode<uint64_t>(encoded);
}

}  // namespace charter::schema::key

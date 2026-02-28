#include <spdlog/spdlog.h>
#include <algorithm>
#include <array>
#include <charter/blake3/hash.hpp>
#include <charter/common/critical.hpp>
#include <charter/crypto/verify.hpp>
#include <charter/execution/engine.hpp>
#include <charter/schema/active_policy_pointer.hpp>
#include <charter/schema/apply_destination_update.hpp>
#include <charter/schema/approval_state.hpp>
#include <charter/schema/approve_destination_update.hpp>
#include <charter/schema/attestation_record.hpp>
#include <charter/schema/destination_update_state.hpp>
#include <charter/schema/encoding/scale/encoder.hpp>
#include <charter/schema/encoding/scale/transaction.hpp>
#include <charter/schema/intent_state.hpp>
#include <charter/schema/propose_destination_update.hpp>
#include <charter/schema/security_event_record.hpp>
#include <charter/schema/set_degraded_mode.hpp>
#include <charter/schema/upsert_role_assignment.hpp>
#include <charter/schema/upsert_signer_quarantine.hpp>
#include <charter/schema/velocity_counter_state.hpp>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <string_view>
#include <tuple>
#include <utility>

using namespace charter::schema;

namespace {

using encoder_t = charter::schema::encoding::encoder<
    charter::schema::encoding::scale_encoder_tag>;

inline constexpr auto kNonceKeyPrefix = std::string_view{"SYS|STATE|NONCE|"};
inline constexpr auto kStatePrefix = std::string_view{"SYS|STATE|"};
inline constexpr auto kWorkspaceKeyPrefix =
    std::string_view{"SYS|STATE|WORKSPACE|"};
inline constexpr auto kVaultKeyPrefix = std::string_view{"SYS|STATE|VAULT|"};
inline constexpr auto kDestinationKeyPrefix =
    std::string_view{"SYS|STATE|DESTINATION|"};
inline constexpr auto kPolicySetKeyPrefix =
    std::string_view{"SYS|STATE|POLICY_SET|"};
inline constexpr auto kActivePolicyPrefix =
    std::string_view{"SYS|STATE|ACTIVE_POLICY|"};
inline constexpr auto kIntentKeyPrefix = std::string_view{"SYS|STATE|INTENT|"};
inline constexpr auto kApprovalKeyPrefix =
    std::string_view{"SYS|STATE|APPROVAL|"};
inline constexpr auto kDestinationUpdateKeyPrefix =
    std::string_view{"SYS|STATE|DESTINATION_UPDATE|"};
inline constexpr auto kAttestationKeyPrefix =
    std::string_view{"SYS|STATE|ATTEST|"};
inline constexpr auto kRoleAssignmentKeyPrefix =
    std::string_view{"SYS|STATE|ROLE_ASSIGNMENT|"};
inline constexpr auto kSignerQuarantineKeyPrefix =
    std::string_view{"SYS|STATE|SIGNER_QUARANTINE|"};
inline constexpr auto kDegradedModeKeyPrefix =
    std::string_view{"SYS|STATE|DEGRADED_MODE|"};
inline constexpr auto kEventSeqKeyPrefix =
    std::string_view{"SYS|STATE|EVENT_SEQ|"};
inline constexpr auto kVelocityKeyPrefix =
    std::string_view{"SYS|STATE|VELOCITY|"};
inline constexpr auto kHistoryPrefix = std::string_view{"SYS|HISTORY|TX|"};
inline constexpr auto kEventPrefix = std::string_view{"SYS|EVENT|"};
inline constexpr auto kSnapshotPrefix = std::string_view{"SYS|SNAP|"};
inline constexpr auto kQueryCodespace = std::string_view{"charter.query"};
inline constexpr auto kExecuteCodespace = std::string_view{"charter.execute"};
inline constexpr auto kCheckTxCodespace = std::string_view{"charter.checktx"};
inline constexpr auto kProposalCodespace = std::string_view{"charter.proposal"};

constexpr auto kEngineKeyspaces = std::array{kNonceKeyPrefix,
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

charter::schema::hash32_t make_chain_id() {
  return charter::blake3::hash(std::string_view{"charter-poc-chain"});
}

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
  auto encoder = encoder_t{};
  return make_prefixed_key(kVaultKeyPrefix,
                           encoder.encode(std::tuple{workspace_id, vault_id}));
}

charter::schema::bytes_t make_destination_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& destination_id) {
  auto encoder = encoder_t{};
  return make_prefixed_key(
      kDestinationKeyPrefix,
      encoder.encode(std::tuple{workspace_id, destination_id}));
}

charter::schema::bytes_t make_nonce_key(
    const charter::schema::signer_id_t& signer) {
  auto encoder = encoder_t{};
  return make_prefixed_key(kNonceKeyPrefix, encoder.encode(signer));
}

charter::schema::bytes_t make_policy_set_key(
    const charter::schema::hash32_t& policy_set_id,
    uint32_t policy_version) {
  auto encoder = encoder_t{};
  return make_prefixed_key(
      kPolicySetKeyPrefix,
      encoder.encode(std::tuple{policy_set_id, policy_version}));
}

charter::schema::bytes_t make_active_policy_key(
    const charter::schema::policy_scope_t& scope) {
  auto encoder = encoder_t{};
  return make_prefixed_key(kActivePolicyPrefix, encoder.encode(scope));
}

charter::schema::bytes_t make_intent_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id,
    const charter::schema::hash32_t& intent_id) {
  auto encoder = encoder_t{};
  return make_prefixed_key(
      kIntentKeyPrefix,
      encoder.encode(std::tuple{workspace_id, vault_id, intent_id}));
}

charter::schema::bytes_t make_approval_key(
    const charter::schema::hash32_t& intent_id,
    const charter::schema::signer_id_t& signer) {
  auto encoder = encoder_t{};
  return make_prefixed_key(kApprovalKeyPrefix,
                           encoder.encode(std::tuple{intent_id, signer}));
}

charter::schema::bytes_t make_destination_update_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& destination_id,
    const charter::schema::hash32_t& update_id) {
  auto encoder = encoder_t{};
  return make_prefixed_key(
      kDestinationUpdateKeyPrefix,
      encoder.encode(std::tuple{workspace_id, destination_id, update_id}));
}

charter::schema::bytes_t make_attestation_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& subject,
    const charter::schema::claim_type_t& claim,
    const charter::schema::signer_id_t& issuer) {
  auto encoder = encoder_t{};
  return make_prefixed_key(
      kAttestationKeyPrefix,
      encoder.encode(std::tuple{workspace_id, subject, claim, issuer}));
}

charter::schema::bytes_t make_attestation_prefix_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& subject,
    const charter::schema::claim_type_t& claim) {
  auto encoder = encoder_t{};
  return make_prefixed_key(
      kAttestationKeyPrefix,
      encoder.encode(std::tuple{workspace_id, subject, claim}));
}

charter::schema::bytes_t make_role_assignment_key(
    const charter::schema::policy_scope_t& scope,
    const charter::schema::signer_id_t& subject,
    const charter::schema::role_id_t role) {
  auto encoder = encoder_t{};
  return make_prefixed_key(kRoleAssignmentKeyPrefix,
                           encoder.encode(std::tuple{scope, subject, role}));
}

charter::schema::bytes_t make_signer_quarantine_key(
    const charter::schema::signer_id_t& signer) {
  auto encoder = encoder_t{};
  return make_prefixed_key(kSignerQuarantineKeyPrefix, encoder.encode(signer));
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
  auto encoder = encoder_t{};
  return make_prefixed_key(kHistoryPrefix,
                           encoder.encode(std::tuple{height, index}));
}

charter::schema::bytes_t make_event_key(uint64_t event_id) {
  auto encoder = encoder_t{};
  return make_prefixed_key(kEventPrefix, encoder.encode(event_id));
}

charter::schema::bytes_t make_velocity_counter_key(
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id,
    const std::optional<charter::schema::asset_id_t>& asset_id,
    const charter::schema::velocity_window_t window,
    const uint64_t window_start_ms) {
  auto encoder = encoder_t{};
  return make_prefixed_key(
      kVelocityKeyPrefix,
      encoder.encode(std::tuple{workspace_id, vault_id, asset_id, window,
                                window_start_ms}));
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
      encoder_t{}.try_decode<std::tuple<uint64_t, uint32_t>>(encoded);
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
  return encoder_t{}.try_decode<uint64_t>(encoded);
}

std::string to_hex(const charter::schema::bytes_view_t& bytes) {
  static constexpr auto kHex = std::string_view{"0123456789abcdef"};
  auto out = std::string{};
  out.resize(bytes.size() * 2);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    out[(2 * i)] = kHex[(bytes[i] >> 4u) & 0x0Fu];
    out[(2 * i) + 1] = kHex[bytes[i] & 0x0Fu];
  }
  return out;
}

std::string payload_type_name(
    const charter::schema::transaction_payload_t& payload) {
  return std::visit(
      overloaded{
          [](const charter::schema::activate_policy_set_t&) {
            return std::string{"activate_policy_set"};
          },
          [](const charter::schema::apply_destination_update_t&) {
            return std::string{"apply_destination_update"};
          },
          [](const charter::schema::approve_destination_update_t&) {
            return std::string{"approve_destination_update"};
          },
          [](const charter::schema::approve_intent_t&) {
            return std::string{"approve_intent"};
          },
          [](const charter::schema::cancel_intent_t&) {
            return std::string{"cancel_intent"};
          },
          [](const charter::schema::create_policy_set_t&) {
            return std::string{"create_policy_set"};
          },
          [](const charter::schema::create_workspace_t&) {
            return std::string{"create_workspace"};
          },
          [](const charter::schema::create_vault_t&) {
            return std::string{"create_vault"};
          },
          [](const charter::schema::execute_intent_t&) {
            return std::string{"execute_intent"};
          },
          [](const charter::schema::propose_destination_update_t&) {
            return std::string{"propose_destination_update"};
          },
          [](const charter::schema::propose_intent_t&) {
            return std::string{"propose_intent"};
          },
          [](const charter::schema::revoke_attestation_t&) {
            return std::string{"revoke_attestation"};
          },
          [](const charter::schema::set_degraded_mode_t&) {
            return std::string{"set_degraded_mode"};
          },
          [](const charter::schema::upsert_attestation_t&) {
            return std::string{"upsert_attestation"};
          },
          [](const charter::schema::upsert_destination_t&) {
            return std::string{"upsert_destination"};
          },
          [](const charter::schema::upsert_role_assignment_t&) {
            return std::string{"upsert_role_assignment"};
          },
          [](const charter::schema::upsert_signer_quarantine_t&) {
            return std::string{"upsert_signer_quarantine"};
          }},
      payload);
}

void append_tx_result_event(charter::execution::tx_result& result,
                            uint64_t height,
                            uint32_t index,
                            const std::optional<charter::schema::transaction_t>&
                                maybe_tx) {
  auto event = charter::execution::tx_event{};
  event.type = "charter.tx_result";
  auto codespace =
      result.codespace.empty() ? std::string{kExecuteCodespace} : result.codespace;
  event.attributes.push_back(charter::execution::tx_event_attribute{
      .key = "code",
      .value = std::to_string(result.code),
      .index = true});
  event.attributes.push_back(charter::execution::tx_event_attribute{
      .key = "success",
      .value = result.code == 0 ? "true" : "false",
      .index = true});
  event.attributes.push_back(charter::execution::tx_event_attribute{
      .key = "codespace", .value = codespace, .index = true});
  event.attributes.push_back(charter::execution::tx_event_attribute{
      .key = "height",
      .value = std::to_string(height),
      .index = true});
  event.attributes.push_back(charter::execution::tx_event_attribute{
      .key = "tx_index",
      .value = std::to_string(index),
      .index = true});
  if (!result.log.empty()) {
    event.attributes.push_back(charter::execution::tx_event_attribute{
        .key = "log", .value = result.log, .index = false});
  }
  if (!result.info.empty()) {
    event.attributes.push_back(charter::execution::tx_event_attribute{
        .key = "info", .value = result.info, .index = false});
  }
  if (maybe_tx.has_value()) {
    auto encoded_signer = encoder_t{}.encode(maybe_tx->signer);
    event.attributes.push_back(charter::execution::tx_event_attribute{
        .key = "signer",
        .value = to_hex(charter::schema::bytes_view_t{
            encoded_signer.data(), encoded_signer.size()}),
        .index = true});
    event.attributes.push_back(charter::execution::tx_event_attribute{
        .key = "nonce",
        .value = std::to_string(maybe_tx->nonce),
        .index = true});
    event.attributes.push_back(charter::execution::tx_event_attribute{
        .key = "payload_type",
        .value = payload_type_name(maybe_tx->payload),
        .index = true});
  } else {
    event.attributes.push_back(charter::execution::tx_event_attribute{
        .key = "payload_type", .value = "decode_failed", .index = true});
  }
  result.events.push_back(std::move(event));
}

std::string make_signer_cache_key(const charter::schema::signer_id_t& signer) {
  auto encoded = encoder_t{}.encode(signer);
  return std::string{reinterpret_cast<const char*>(encoded.data()),
                     encoded.size()};
}

bool signer_ids_equal(const charter::schema::signer_id_t& lhs,
                      const charter::schema::signer_id_t& rhs) {
  auto encoder = encoder_t{};
  return encoder.encode(lhs) == encoder.encode(rhs);
}

std::optional<charter::schema::policy_scope_t> scope_from_payload(
    const charter::schema::transaction_payload_t& payload) {
  return std::visit(
      overloaded{
          [&](const charter::schema::create_workspace_t&)
              -> std::optional<charter::schema::policy_scope_t> {
            return std::nullopt;
          },
          [&](const charter::schema::create_vault_t& op)
              -> std::optional<charter::schema::policy_scope_t> {
            return charter::schema::policy_scope_t{
                charter::schema::workspace_scope_t{.workspace_id =
                                                       op.workspace_id}};
          },
          [&](const charter::schema::upsert_destination_t& op)
              -> std::optional<charter::schema::policy_scope_t> {
            return charter::schema::policy_scope_t{
                charter::schema::workspace_scope_t{.workspace_id =
                                                       op.workspace_id}};
          },
          [&](const charter::schema::create_policy_set_t& op)
              -> std::optional<charter::schema::policy_scope_t> {
            return op.scope;
          },
          [&](const charter::schema::activate_policy_set_t& op)
              -> std::optional<charter::schema::policy_scope_t> {
            return op.scope;
          },
          [&](const charter::schema::propose_intent_t& op)
              -> std::optional<charter::schema::policy_scope_t> {
            return charter::schema::policy_scope_t{charter::schema::vault_t{
                .workspace_id = op.workspace_id, .vault_id = op.vault_id}};
          },
          [&](const charter::schema::approve_intent_t& op)
              -> std::optional<charter::schema::policy_scope_t> {
            return charter::schema::policy_scope_t{charter::schema::vault_t{
                .workspace_id = op.workspace_id, .vault_id = op.vault_id}};
          },
          [&](const charter::schema::execute_intent_t& op)
              -> std::optional<charter::schema::policy_scope_t> {
            return charter::schema::policy_scope_t{charter::schema::vault_t{
                .workspace_id = op.workspace_id, .vault_id = op.vault_id}};
          },
          [&](const charter::schema::cancel_intent_t& op)
              -> std::optional<charter::schema::policy_scope_t> {
            return charter::schema::policy_scope_t{charter::schema::vault_t{
                .workspace_id = op.workspace_id, .vault_id = op.vault_id}};
          },
          [&](const charter::schema::upsert_attestation_t& op)
              -> std::optional<charter::schema::policy_scope_t> {
            return charter::schema::policy_scope_t{
                charter::schema::workspace_scope_t{.workspace_id =
                                                       op.workspace_id}};
          },
          [&](const charter::schema::revoke_attestation_t& op)
              -> std::optional<charter::schema::policy_scope_t> {
            return charter::schema::policy_scope_t{
                charter::schema::workspace_scope_t{.workspace_id =
                                                       op.workspace_id}};
          },
          [&](const charter::schema::propose_destination_update_t& op)
              -> std::optional<charter::schema::policy_scope_t> {
            return charter::schema::policy_scope_t{
                charter::schema::workspace_scope_t{.workspace_id =
                                                       op.workspace_id}};
          },
          [&](const charter::schema::approve_destination_update_t& op)
              -> std::optional<charter::schema::policy_scope_t> {
            return charter::schema::policy_scope_t{
                charter::schema::workspace_scope_t{.workspace_id =
                                                       op.workspace_id}};
          },
          [&](const charter::schema::apply_destination_update_t& op)
              -> std::optional<charter::schema::policy_scope_t> {
            return charter::schema::policy_scope_t{
                charter::schema::workspace_scope_t{.workspace_id =
                                                       op.workspace_id}};
          },
          [&](const charter::schema::upsert_role_assignment_t& op)
              -> std::optional<charter::schema::policy_scope_t> {
            return op.scope;
          },
          [&](const charter::schema::upsert_signer_quarantine_t&)
              -> std::optional<charter::schema::policy_scope_t> {
            return std::nullopt;
          },
          [&](const charter::schema::set_degraded_mode_t&)
              -> std::optional<charter::schema::policy_scope_t> {
            return std::nullopt;
          }},
      payload);
}

std::vector<charter::schema::role_id_t> required_roles_for_payload(
    const charter::schema::transaction_payload_t& payload) {
  using role_t = charter::schema::role_id_t;
  return std::visit(
      overloaded{[&](const charter::schema::create_workspace_t&) {
                   return std::vector<role_t>{};
                 },
                 [&](const charter::schema::create_vault_t&) {
                   return std::vector<role_t>{role_t::admin};
                 },
                 [&](const charter::schema::upsert_destination_t&) {
                   return std::vector<role_t>{role_t::admin};
                 },
                 [&](const charter::schema::create_policy_set_t&) {
                   return std::vector<role_t>{role_t::admin};
                 },
                 [&](const charter::schema::activate_policy_set_t&) {
                   return std::vector<role_t>{role_t::admin};
                 },
                 [&](const charter::schema::propose_intent_t&) {
                   return std::vector<role_t>{role_t::initiator};
                 },
                 [&](const charter::schema::approve_intent_t&) {
                   return std::vector<role_t>{role_t::approver};
                 },
                 [&](const charter::schema::execute_intent_t&) {
                   return std::vector<role_t>{role_t::executor};
                 },
                 [&](const charter::schema::cancel_intent_t&) {
                   return std::vector<role_t>{role_t::initiator, role_t::admin};
                 },
                 [&](const charter::schema::upsert_attestation_t&) {
                   return std::vector<role_t>{role_t::attestor, role_t::admin};
                 },
                 [&](const charter::schema::revoke_attestation_t&) {
                   return std::vector<role_t>{role_t::attestor, role_t::admin};
                 },
                 [&](const charter::schema::propose_destination_update_t&) {
                   return std::vector<role_t>{role_t::admin};
                 },
                 [&](const charter::schema::approve_destination_update_t&) {
                   return std::vector<role_t>{role_t::approver, role_t::admin};
                 },
                 [&](const charter::schema::apply_destination_update_t&) {
                   return std::vector<role_t>{role_t::executor, role_t::admin};
                 },
                 [&](const charter::schema::upsert_role_assignment_t&) {
                   return std::vector<role_t>{role_t::admin};
                 },
                 [&](const charter::schema::upsert_signer_quarantine_t&) {
                   return std::vector<role_t>{role_t::guardian, role_t::admin};
                 },
                 [&](const charter::schema::set_degraded_mode_t&) {
                   return std::vector<role_t>{role_t::guardian, role_t::admin};
                 }},
      payload);
}

bool workspace_exists(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::hash32_t& workspace_id) {
  auto key = make_workspace_key(workspace_id);
  auto workspace = storage.get<encoder_t, charter::schema::workspace_state_t>(
      encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  return workspace.has_value();
}

bool vault_exists(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id) {
  auto key = make_vault_key(workspace_id, vault_id);
  auto vault = storage.get<encoder_t, charter::schema::vault_state_t>(
      encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  return vault.has_value();
}

bool destination_enabled(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& destination_id) {
  auto key = make_destination_key(workspace_id, destination_id);
  auto destination =
      storage.get<encoder_t, charter::schema::destination_state_t>(
          encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  return destination.has_value() && destination->enabled;
}

std::optional<charter::schema::degraded_mode_state_t> load_degraded_mode_state(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder) {
  auto key = make_degraded_mode_key();
  return storage.get<encoder_t, charter::schema::degraded_mode_state_t>(
      encoder, charter::schema::bytes_view_t{key.data(), key.size()});
}

charter::schema::degraded_mode_t current_degraded_mode(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder) {
  auto state = load_degraded_mode_state(storage, encoder);
  if (!state.has_value()) {
    return charter::schema::degraded_mode_t::normal;
  }
  return state->mode;
}

bool signer_quarantined(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::signer_id_t& signer,
    const uint64_t now_ms) {
  auto key = make_signer_quarantine_key(signer);
  auto state =
      storage.get<encoder_t, charter::schema::signer_quarantine_state_t>(
          encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  if (!state.has_value() || !state->quarantined) {
    return false;
  }
  if (!state->until.has_value()) {
    return true;
  }
  return now_ms <= state->until.value();
}

void append_security_event(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::security_event_type_t type,
    const charter::schema::security_event_severity_t severity,
    const uint32_t code,
    const std::string_view message,
    const std::optional<charter::schema::signer_id_t>& signer,
    const std::optional<charter::schema::hash32_t>& workspace_id,
    const std::optional<charter::schema::hash32_t>& vault_id,
    const uint64_t now_ms,
    const uint64_t block_height) {
  auto seq_key = make_event_sequence_key();
  auto next_id = storage
                     .get<encoder_t, uint64_t>(
                         encoder, charter::schema::bytes_view_t{seq_key.data(),
                                                                seq_key.size()})
                     .value_or(1);
  auto event_key = make_event_key(next_id);
  storage.put(encoder,
              charter::schema::bytes_view_t{event_key.data(), event_key.size()},
              charter::schema::security_event_record_t{
                  .event_id = next_id,
                  .height = block_height,
                  .tx_index = 0,
                  .type = type,
                  .severity = severity,
                  .code = code,
                  .message = charter::schema::make_bytes(message),
                  .signer = signer,
                  .workspace_id = workspace_id,
                  .vault_id = vault_id,
                  .recorded_at = now_ms});
  storage.put(encoder,
              charter::schema::bytes_view_t{seq_key.data(), seq_key.size()},
              next_id + 1);
}

bool policy_scope_exists(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::policy_scope_t& scope) {
  auto found = false;
  std::visit(
      overloaded{[&](const charter::schema::workspace_scope_t& value) {
                   found =
                       workspace_exists(storage, encoder, value.workspace_id);
                 },
                 [&](const charter::schema::vault_t& value) {
                   found =
                       workspace_exists(storage, encoder, value.workspace_id) &&
                       vault_exists(storage, encoder, value.workspace_id,
                                    value.vault_id);
                 }},
      scope);
  return found;
}

bool active_policy_exists(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::policy_scope_t& scope) {
  auto key = make_active_policy_key(scope);
  auto pointer =
      storage.get<encoder_t, charter::schema::active_policy_pointer_t>(
          encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  return pointer.has_value();
}

charter::schema::operation_type_t operation_type_from_intent_action(
    const charter::schema::intent_action_t& action) {
  auto type = charter::schema::operation_type_t::transfer;
  std::visit(overloaded{[&](const charter::schema::transfer_parameters_t&) {
               type = charter::schema::operation_type_t::transfer;
             }},
             action);
  return type;
}

struct policy_requirements final {
  uint32_t threshold{1};
  uint64_t delay_ms{};
  charter::schema::hash32_t policy_set_id;
  uint32_t policy_version{};
  std::optional<charter::schema::amount_t> per_transaction_limit;
  bool require_whitelisted_destination{};
  bool require_distinct_from_initiator{};
  bool require_distinct_from_executor{};
  std::vector<charter::schema::claim_requirement_t> claim_requirements;
  std::vector<charter::schema::velocity_limit_rule_t> velocity_limits;
};

std::optional<policy_requirements> resolve_policy_requirements(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::policy_scope_t& scope,
    const charter::schema::operation_type_t operation_type) {
  auto active_key = make_active_policy_key(scope);
  auto pointer =
      storage.get<encoder_t, charter::schema::active_policy_pointer_t>(
          encoder,
          charter::schema::bytes_view_t{active_key.data(), active_key.size()});
  if (!pointer) {
    return std::nullopt;
  }
  auto policy_key =
      make_policy_set_key(pointer->policy_set_id, pointer->policy_set_version);
  auto policy = storage.get<encoder_t, charter::schema::policy_set_state_t>(
      encoder,
      charter::schema::bytes_view_t{policy_key.data(), policy_key.size()});
  if (!policy) {
    return std::nullopt;
  }

  auto requirements = policy_requirements{};
  requirements.policy_set_id = pointer->policy_set_id;
  requirements.policy_version = pointer->policy_set_version;

  for (const auto& rule : policy->rules) {
    if (rule.operation != operation_type) {
      continue;
    }
    for (const auto& approval : rule.approvals) {
      requirements.threshold =
          std::max(requirements.threshold, approval.threshold);
      requirements.require_distinct_from_initiator =
          requirements.require_distinct_from_initiator ||
          approval.require_distinct_from_initiator;
      requirements.require_distinct_from_executor =
          requirements.require_distinct_from_executor ||
          approval.require_distinct_from_executor;
    }
    if (rule.time_locks.has_value()) {
      for (const auto& time_lock : *rule.time_locks) {
        if (time_lock.operation == operation_type) {
          requirements.delay_ms =
              std::max(requirements.delay_ms, time_lock.delay);
        }
      }
    }
    for (const auto& limit : rule.limits) {
      if (!requirements.per_transaction_limit.has_value() ||
          limit.per_transaction_amount <
              requirements.per_transaction_limit.value()) {
        requirements.per_transaction_limit = limit.per_transaction_amount;
      }
    }
    for (const auto& destination_rule : rule.destination_rules) {
      requirements.require_whitelisted_destination =
          requirements.require_whitelisted_destination ||
          destination_rule.require_whitelisted;
    }
    for (const auto& claim : rule.required_claims) {
      auto existing = std::find_if(
          std::begin(requirements.claim_requirements),
          std::end(requirements.claim_requirements),
          [&](const charter::schema::claim_requirement_t& requirement) {
            return requirement.claim == claim;
          });
      if (existing == std::end(requirements.claim_requirements)) {
        requirements.claim_requirements.push_back(
            charter::schema::claim_requirement_t{
                .claim = claim,
                .minimum_valid_until = std::nullopt,
                .trusted_issuers = std::nullopt});
      }
    }
    for (const auto& velocity_limit : rule.velocity_limits) {
      requirements.velocity_limits.push_back(velocity_limit);
    }
  }
  return requirements;
}

std::optional<charter::schema::policy_set_state_t> load_policy_set(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::hash32_t& policy_set_id,
    const uint32_t policy_version) {
  auto key = make_policy_set_key(policy_set_id, policy_version);
  return storage.get<encoder_t, charter::schema::policy_set_state_t>(
      encoder, charter::schema::bytes_view_t{key.data(), key.size()});
}

std::optional<charter::schema::policy_set_state_t>
load_active_policy_set_for_scope(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::policy_scope_t& scope) {
  auto active_key = make_active_policy_key(scope);
  auto pointer =
      storage.get<encoder_t, charter::schema::active_policy_pointer_t>(
          encoder,
          charter::schema::bytes_view_t{active_key.data(), active_key.size()});
  if (!pointer) {
    return std::nullopt;
  }
  return load_policy_set(storage, encoder, pointer->policy_set_id,
                         pointer->policy_set_version);
}

bool role_granted_by_policy(const charter::schema::policy_set_state_t& policy,
                            const charter::schema::role_id_t role,
                            const charter::schema::signer_id_t& signer) {
  auto role_it = std::find_if(
      std::begin(policy.roles), std::end(policy.roles),
      [&](const std::pair<charter::schema::role_id_t,
                          std::vector<charter::schema::signer_id_t>>& entry) {
        return entry.first == role;
      });
  if (role_it == std::end(policy.roles)) {
    return false;
  }
  return std::any_of(std::begin(role_it->second), std::end(role_it->second),
                     [&](const charter::schema::signer_id_t& candidate) {
                       return signer_ids_equal(candidate, signer);
                     });
}

bool role_granted_by_override(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::policy_scope_t& scope,
    const charter::schema::signer_id_t& signer,
    const charter::schema::role_id_t role,
    const uint64_t now_ms,
    std::optional<bool>& has_override) {
  auto key = make_role_assignment_key(scope, signer, role);
  auto assignment =
      storage.get<encoder_t, charter::schema::role_assignment_state_t>(
          encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  if (!assignment.has_value()) {
    has_override = std::nullopt;
    return false;
  }
  has_override = assignment->enabled;
  if (!assignment->enabled) {
    return false;
  }
  if (assignment->not_before.has_value() &&
      now_ms < assignment->not_before.value()) {
    return false;
  }
  if (assignment->expires_at.has_value() &&
      now_ms > assignment->expires_at.value()) {
    return false;
  }
  return true;
}

bool scope_has_role(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::policy_scope_t& scope,
    const charter::schema::signer_id_t& signer,
    const charter::schema::role_id_t role,
    const uint64_t now_ms) {
  auto has_override = std::optional<bool>{};
  if (role_granted_by_override(storage, encoder, scope, signer, role, now_ms,
                               has_override)) {
    return true;
  }
  if (has_override.has_value()) {
    return false;
  }
  auto policy = load_active_policy_set_for_scope(storage, encoder, scope);
  if (!policy.has_value()) {
    return false;
  }
  return role_granted_by_policy(policy.value(), role, signer);
}

bool signer_has_role_for_scope(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::policy_scope_t& scope,
    const charter::schema::signer_id_t& signer,
    const charter::schema::role_id_t role,
    const uint64_t now_ms) {
  if (scope_has_role(storage, encoder, scope, signer, role, now_ms)) {
    return true;
  }
  // Scope admins are allowed to satisfy operation roles as a superuser
  // fallback for operational recovery.
  if (role != charter::schema::role_id_t::admin &&
      scope_has_role(storage, encoder, scope, signer,
                     charter::schema::role_id_t::admin, now_ms)) {
    return true;
  }
  if (std::holds_alternative<charter::schema::vault_t>(scope)) {
    const auto& vault = std::get<charter::schema::vault_t>(scope);
    auto workspace_scope = charter::schema::policy_scope_t{
        charter::schema::workspace_scope_t{.workspace_id = vault.workspace_id}};
    if (scope_has_role(storage, encoder, workspace_scope, signer, role,
                       now_ms)) {
      return true;
    }
    if (role != charter::schema::role_id_t::admin &&
        scope_has_role(storage, encoder, workspace_scope, signer,
                       charter::schema::role_id_t::admin, now_ms)) {
      return true;
    }
  }
  return false;
}

bool signer_has_required_global_role(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::signer_id_t& signer,
    const std::vector<charter::schema::role_id_t>& required_roles,
    const uint64_t now_ms) {
  auto prefix = charter::schema::make_bytes(kRoleAssignmentKeyPrefix);
  auto rows = storage.list_by_prefix(
      charter::schema::bytes_view_t{prefix.data(), prefix.size()});
  for (const auto& [unused_key, value] : rows) {
    (void)unused_key;
    auto assignment =
        encoder.try_decode<charter::schema::role_assignment_state_t>(
            charter::schema::bytes_view_t{value.data(), value.size()});
    if (!assignment.has_value()) {
      continue;
    }
    if (!signer_ids_equal(assignment->subject, signer)) {
      continue;
    }
    if (!assignment->enabled) {
      continue;
    }
    if (assignment->not_before.has_value() &&
        now_ms < assignment->not_before.value()) {
      continue;
    }
    if (assignment->expires_at.has_value() &&
        now_ms > assignment->expires_at.value()) {
      continue;
    }
    if (assignment->role == charter::schema::role_id_t::admin) {
      return true;
    }
    if (std::find(std::begin(required_roles), std::end(required_roles),
                  assignment->role) != std::end(required_roles)) {
      return true;
    }
  }
  return false;
}

bool is_policy_denial_code(const uint32_t code) {
  switch (code) {
    case 20:
    case 23:
    case 26:
    case 28:
    case 29:
    case 30:
    case 34:
    case 35:
    case 39:
      return true;
    default:
      return false;
  }
}

charter::schema::security_event_type_t event_type_for_tx_error(
    const uint32_t code,
    const bool validation_phase) {
  if (code == 33) {
    return charter::schema::security_event_type_t::authz_denied;
  }
  if (is_policy_denial_code(code)) {
    return charter::schema::security_event_type_t::policy_denied;
  }
  return validation_phase
             ? charter::schema::security_event_type_t::tx_validation_failed
             : charter::schema::security_event_type_t::tx_execution_denied;
}

uint64_t velocity_window_start_ms(
    const uint64_t now_ms,
    const charter::schema::velocity_window_t window) {
  constexpr auto kDayMs = uint64_t{24} * 60 * 60 * 1000;
  switch (window) {
    case charter::schema::velocity_window_t::daily:
      return (now_ms / kDayMs) * kDayMs;
    case charter::schema::velocity_window_t::weekly:
      return (now_ms / (7 * kDayMs)) * (7 * kDayMs);
    case charter::schema::velocity_window_t::monthly:
      // Deterministic fixed 30-day bucket for PoC.
      return (now_ms / (30 * kDayMs)) * (30 * kDayMs);
  }
  return 0;
}

std::optional<std::pair<charter::schema::hash32_t, uint64_t>>
transfer_asset_and_amount(const charter::schema::intent_action_t& action) {
  return std::visit(
      overloaded{
          [](const charter::schema::transfer_parameters_t& transfer)
              -> std::optional<std::pair<charter::schema::hash32_t, uint64_t>> {
            return std::pair{transfer.asset_id, transfer.amount};
          }},
      action);
}

charter::execution::tx_result make_error_tx_result(uint32_t code,
                                                   std::string log,
                                                   std::string info,
                                                   std::string codespace);

bool enforce_velocity_limits(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id,
    const charter::schema::intent_action_t& action,
    const std::vector<charter::schema::velocity_limit_rule_t>& limits,
    const uint64_t now_ms,
    charter::execution::tx_result& result,
    const std::string_view codespace) {
  auto transfer = transfer_asset_and_amount(action);
  if (!transfer.has_value()) {
    return true;
  }
  const auto& [asset_id, amount] = transfer.value();
  for (const auto& limit : limits) {
    if (limit.asset_id.has_value() && limit.asset_id.value() != asset_id) {
      continue;
    }
    auto window_start = velocity_window_start_ms(now_ms, limit.window);
    auto key = make_velocity_counter_key(workspace_id, vault_id, limit.asset_id,
                                         limit.window, window_start);
    auto counter =
        storage.get<encoder_t, charter::schema::velocity_counter_state_t>(
            encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    auto used = counter.has_value() ? counter->used_amount
                                    : charter::schema::amount_t{0};
    if (used + charter::schema::amount_t{amount} > limit.maximum_amount) {
      result = make_error_tx_result(
          34, "velocity limit exceeded",
          "cumulative velocity window amount exceeded policy maximum",
          std::string{codespace});
      return false;
    }
  }
  return true;
}

void apply_velocity_limits(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id,
    const charter::schema::intent_action_t& action,
    const std::vector<charter::schema::velocity_limit_rule_t>& limits,
    const uint64_t now_ms) {
  auto transfer = transfer_asset_and_amount(action);
  if (!transfer.has_value()) {
    return;
  }
  const auto& [asset_id, amount] = transfer.value();
  for (const auto& limit : limits) {
    if (limit.asset_id.has_value() && limit.asset_id.value() != asset_id) {
      continue;
    }
    auto window_start = velocity_window_start_ms(now_ms, limit.window);
    auto key = make_velocity_counter_key(workspace_id, vault_id, limit.asset_id,
                                         limit.window, window_start);
    auto counter =
        storage.get<encoder_t, charter::schema::velocity_counter_state_t>(
            encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    auto state = counter.value_or(charter::schema::velocity_counter_state_t{
        .workspace_id = workspace_id,
        .vault_id = vault_id,
        .asset_id = limit.asset_id,
        .window = limit.window,
        .window_start = window_start});
    state.used_amount += charter::schema::amount_t{amount};
    state.tx_count += 1;
    storage.put(encoder, charter::schema::bytes_view_t{key.data(), key.size()},
                state);
  }
}

bool attestation_satisfies_requirement(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    encoder_t& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& subject,
    const charter::schema::claim_requirement_t& requirement,
    uint64_t now_ms) {
  auto matches_record =
      [&](const charter::schema::attestation_record_t& record) {
        if (record.status != charter::schema::attestation_status_t::active) {
          return false;
        }
        if (record.expires_at < now_ms) {
          return false;
        }
        if (requirement.minimum_valid_until.has_value() &&
            record.expires_at < requirement.minimum_valid_until.value()) {
          return false;
        }
        return true;
      };

  if (requirement.trusted_issuers.has_value()) {
    for (const auto& issuer : *requirement.trusted_issuers) {
      auto key = make_attestation_key(workspace_id, subject, requirement.claim,
                                      issuer);
      auto record =
          storage.get<encoder_t, charter::schema::attestation_record_t>(
              encoder, charter::schema::bytes_view_t{key.data(), key.size()});
      if (record.has_value() && matches_record(record.value())) {
        return true;
      }
    }
    return false;
  }

  auto prefix =
      make_attestation_prefix_key(workspace_id, subject, requirement.claim);
  auto rows = storage.list_by_prefix(
      charter::schema::bytes_view_t{prefix.data(), prefix.size()});
  for (const auto& [unused_key, value] : rows) {
    (void)unused_key;
    auto record = encoder.try_decode<charter::schema::attestation_record_t>(
        charter::schema::bytes_view_t{value.data(), value.size()});
    if (record.has_value() && matches_record(record.value())) {
      return true;
    }
  }
  return false;
}

charter::execution::tx_result make_error_tx_result(uint32_t code,
                                                   std::string log,
                                                   std::string info,
                                                   std::string codespace) {
  spdlog::error("tx error: code={} codespace='{}' log='{}' info='{}'", code,
                codespace, log, info);
  auto result = charter::execution::tx_result{};
  result.code = code;
  result.log = std::move(log);
  result.info = std::move(info);
  result.codespace = std::move(codespace);
  return result;
}

charter::execution::query_result make_error_query_result(
    uint32_t code,
    std::string log,
    std::string info,
    std::string codespace,
    int64_t height,
    const charter::schema::bytes_view_t& key) {
  spdlog::error("query error: code={} codespace='{}' log='{}' info='{}'", code,
                codespace, log, info);
  auto result = charter::execution::query_result{};
  result.code = code;
  result.log = std::move(log);
  result.info = std::move(info);
  result.key = charter::schema::make_bytes(key);
  result.codespace = std::move(codespace);
  result.height = height;
  return result;
}

bool signer_signature_compatible(
    const charter::schema::signer_id_t& signer,
    const charter::schema::signature_t& signature) {
  auto compatible = true;
  std::visit(
      overloaded{
          [&](const charter::schema::ed25519_signer_id&) {
            compatible =
                std::holds_alternative<charter::schema::ed25519_signature_t>(
                    signature);
          },
          [&](const charter::schema::secp256k1_signer_id&) {
            compatible =
                std::holds_alternative<charter::schema::secp256k1_signature_t>(
                    signature);
          },
          [&](const charter::schema::named_signer_t&) { compatible = true; }},
      signer);
  return compatible;
}

charter::schema::bytes_t make_signing_bytes(
    const charter::schema::transaction_t& tx) {
  auto encoder = encoder_t{};
  return encoder.encode(
      std::tuple{tx.version, tx.chain_id, tx.nonce, tx.signer, tx.payload});
}

charter::schema::hash32_t fold_app_hash(const charter::schema::hash32_t& seed,
                                        const charter::schema::bytes_t& tx,
                                        uint64_t height,
                                        uint64_t index) {
  auto material = charter::schema::bytes_t{};
  material.reserve(seed.size() + tx.size() + 32);
  material.insert(std::end(material), std::begin(seed), std::end(seed));
  material.insert(std::end(material), std::begin(tx), std::end(tx));

  auto encoder = encoder_t{};
  auto encoded_suffix = encoder.encode(std::tuple{height, index});
  material.insert(std::end(material), std::begin(encoded_suffix),
                  std::end(encoded_suffix));
  return charter::blake3::hash(
      charter::schema::bytes_view_t{material.data(), material.size()});
}

std::optional<charter::schema::transaction_t> decode_transaction(
    const charter::schema::bytes_view_t& raw_tx,
    std::string& error) {
  if (raw_tx.empty()) {
    error = "empty transaction";
    return std::nullopt;
  }
  auto encoder = encoder_t{};
  auto tx = encoder.try_decode<charter::schema::transaction_t>(raw_tx);
  if (!tx) {
    error = "failed to decode transaction";
    return std::nullopt;
  }
  return tx;
}

charter::execution::snapshot_descriptor make_snapshot_descriptor(
    uint64_t height,
    const charter::schema::bytes_t& chunk) {
  auto snapshot = charter::execution::snapshot_descriptor{};
  snapshot.height = height;
  snapshot.format = 1;
  snapshot.chunks = 1;
  snapshot.hash = charter::blake3::hash(
      charter::schema::bytes_view_t{chunk.data(), chunk.size()});
  snapshot.metadata =
      charter::schema::make_bytes(std::string_view{"charter-snapshot-v1"});
  return snapshot;
}

charter::schema::bytes_t make_state_prefix_bytes() {
  return charter::schema::make_bytes(kStatePrefix);
}

charter::schema::bytes_t make_state_snapshot_chunk(
    const charter::storage::storage<charter::storage::rocksdb_storage_tag>&
        storage) {
  auto prefix = make_state_prefix_bytes();
  auto state_entries = storage.list_by_prefix(
      charter::schema::bytes_view_t{prefix.data(), prefix.size()});
  auto encoder = encoder_t{};
  auto chunk = encoder.encode(std::tuple{uint16_t{1}, state_entries});
  spdlog::debug("Built snapshot chunk with {} state records",
                state_entries.size());
  return chunk;
}

bool restore_state_snapshot_chunk(
    const charter::storage::storage<charter::storage::rocksdb_storage_tag>&
        storage,
    const charter::schema::bytes_view_t& chunk,
    std::string& error) {
  auto encoder = encoder_t{};
  auto decoded = encoder.try_decode<
      std::tuple<uint16_t, std::vector<charter::storage::key_value_entry_t>>>(
      chunk);
  if (!decoded.has_value()) {
    error = "failed to decode snapshot chunk";
    return false;
  }
  auto version = std::get<0>(decoded.value());
  if (version != 1) {
    error = "unsupported snapshot chunk version";
    return false;
  }
  auto prefix = make_state_prefix_bytes();
  storage.replace_by_prefix(
      charter::schema::bytes_view_t{prefix.data(), prefix.size()},
      std::get<1>(decoded.value()));
  return true;
}

}  // namespace

namespace charter::execution {

engine::engine(uint64_t snapshot_interval,
               std::string db_path,
               bool require_strict_crypto)
    : db_path_{std::move(db_path)},
      chain_id_{make_chain_id()},
      snapshot_interval_{snapshot_interval} {
  auto lock = std::scoped_lock{mutex_};
  spdlog::info(
      "Initializing execution engine: db_path='{}' snapshot_interval={} "
      "strict_crypto={} chain_id={}",
      db_path_, snapshot_interval_, require_strict_crypto,
      to_hex(
          charter::schema::bytes_view_t{chain_id_.data(), chain_id_.size()}));

  storage_ =
      charter::storage::make_storage<charter::storage::rocksdb_storage_tag>(
          db_path_);
  load_persisted_state();

  if (last_committed_state_root_.empty()) {
    last_committed_state_root_ = make_zero_hash();
    pending_state_root_ = last_committed_state_root_;
    storage_.save_committed_state(charter::storage::committed_state{
        .height = last_committed_height_,
        .state_root = last_committed_state_root_});
  }
  if (snapshot_interval_ == 0) {
    spdlog::warn("Snapshot interval is 0; snapshots disabled");
  }
  if (charter::crypto::available()) {
    signature_verifier_ = charter::crypto::verify_signature;
  } else {
    if (require_strict_crypto) {
      charter::common::critical(
          "OpenSSL backend unavailable for strict signature verification");
    }
    spdlog::warn(
        "OpenSSL backend unavailable for full signature verification; "
        "falling back to compatibility-only checks");
    signature_verifier_ = [](const charter::schema::bytes_view_t&,
                             const charter::schema::signer_id_t&,
                             const charter::schema::signature_t&) {
      return true;
    };
  }
  spdlog::info("Execution engine ready at height {} with {} snapshot(s)",
               last_committed_height_, snapshots_.size());
}

tx_result engine::check_tx(const charter::schema::bytes_view_t& raw_tx) {
  auto lock = std::scoped_lock{mutex_};
  auto decode_error = std::string{};
  auto maybe_tx = decode_transaction(
      charter::schema::bytes_view_t{raw_tx.data(), raw_tx.size()},
      decode_error);
  if (!maybe_tx) {
    return make_error_tx_result(1, "invalid transaction", decode_error,
                                std::string{kCheckTxCodespace});
  }
  auto result = validate_tx(*maybe_tx, kCheckTxCodespace, std::nullopt);
  if (result.code != 0) {
    return result;
  }
  result.gas_wanted = 1000;
  return result;
}

tx_result engine::process_proposal_tx(
    const charter::schema::bytes_view_t& raw_tx) {
  auto lock = std::scoped_lock{mutex_};
  auto decode_error = std::string{};
  auto maybe_tx = decode_transaction(raw_tx, decode_error);
  if (!maybe_tx) {
    return make_error_tx_result(1, "invalid transaction", decode_error,
                                std::string{kProposalCodespace});
  }
  auto result = validate_tx(*maybe_tx, kProposalCodespace, std::nullopt);
  if (result.code == 0) {
    result.gas_wanted = 1000;
  }
  return result;
}

tx_result engine::execute_operation(const charter::schema::transaction_t& tx) {
  auto result = tx_result{};
  auto encoder = encoder_t{};
  std::visit(
      overloaded{
          [&](const charter::schema::create_workspace_t& operation) {
            auto workspace_key = make_workspace_key(operation.workspace_id);
            if (workspace_exists(storage_, encoder, operation.workspace_id)) {
              result = make_error_tx_result(10, "workspace already exists",
                                            "workspace_id already present",
                                            std::string{kExecuteCodespace});
              return;
            }
            storage_.put(encoder,
                         charter::schema::bytes_view_t{workspace_key.data(),
                                                       workspace_key.size()},
                         charter::schema::workspace_state_t{operation});
            auto scope = charter::schema::policy_scope_t{
                charter::schema::workspace_scope_t{.workspace_id =
                                                       operation.workspace_id}};
            for (const auto& admin : operation.admin_set) {
              auto role_key = make_role_assignment_key(
                  scope, admin, charter::schema::role_id_t::admin);
              storage_.put(encoder,
                           charter::schema::bytes_view_t{role_key.data(),
                                                         role_key.size()},
                           charter::schema::role_assignment_state_t{
                               .scope = scope,
                               .subject = admin,
                               .role = charter::schema::role_id_t::admin,
                               .enabled = true,
                               .not_before = std::nullopt,
                               .expires_at = std::nullopt,
                               .note = std::nullopt});
            }
            result.info = "create_workspace persisted";
          },
          [&](const charter::schema::create_vault_t& operation) {
            if (!workspace_exists(storage_, encoder, operation.workspace_id)) {
              result = make_error_tx_result(
                  11, "workspace missing",
                  "workspace must exist before vault creation",
                  std::string{kExecuteCodespace});
              return;
            }
            auto vault_key =
                make_vault_key(operation.workspace_id, operation.vault_id);
            if (vault_exists(storage_, encoder, operation.workspace_id,
                             operation.vault_id)) {
              result = make_error_tx_result(12, "vault already exists",
                                            "vault_id already present",
                                            std::string{kExecuteCodespace});
              return;
            }
            storage_.put(encoder,
                         charter::schema::bytes_view_t{vault_key.data(),
                                                       vault_key.size()},
                         charter::schema::vault_state_t{operation});
            result.info = "create_vault persisted";
          },
          [&](const charter::schema::upsert_destination_t& operation) {
            if (!workspace_exists(storage_, encoder, operation.workspace_id)) {
              result = make_error_tx_result(
                  11, "workspace missing",
                  "workspace must exist before destination upsert",
                  std::string{kExecuteCodespace});
              return;
            }
            auto destination_key = make_destination_key(
                operation.workspace_id, operation.destination_id);
            storage_.put(encoder,
                         charter::schema::bytes_view_t{destination_key.data(),
                                                       destination_key.size()},
                         charter::schema::destination_state_t{operation});
            result.info = "upsert_destination persisted";
          },
          [&](const charter::schema::create_policy_set_t& operation) {
            if (!policy_scope_exists(storage_, encoder, operation.scope)) {
              result = make_error_tx_result(13, "policy scope missing",
                                            "scope target does not exist",
                                            std::string{kExecuteCodespace});
              return;
            }
            auto policy_key = make_policy_set_key(
                operation.policy_set_id,
                static_cast<uint32_t>(operation.policy_version));
            auto existing =
                storage_.get<encoder_t, charter::schema::policy_set_state_t>(
                    encoder, charter::schema::bytes_view_t{policy_key.data(),
                                                           policy_key.size()});
            if (existing) {
              result =
                  make_error_tx_result(14, "policy set already exists",
                                       "policy_set_id/version already present",
                                       std::string{kExecuteCodespace});
              return;
            }
            storage_.put(encoder,
                         charter::schema::bytes_view_t{policy_key.data(),
                                                       policy_key.size()},
                         charter::schema::policy_set_state_t{operation});
            result.info = "create_policy_set persisted";
          },
          [&](const charter::schema::activate_policy_set_t& operation) {
            if (!policy_scope_exists(storage_, encoder, operation.scope)) {
              result = make_error_tx_result(13, "policy scope missing",
                                            "scope target does not exist",
                                            std::string{kExecuteCodespace});
              return;
            }
            auto policy_key = make_policy_set_key(operation.policy_set_id,
                                                  operation.policy_set_version);
            auto policy =
                storage_.get<encoder_t, charter::schema::policy_set_state_t>(
                    encoder, charter::schema::bytes_view_t{policy_key.data(),
                                                           policy_key.size()});
            if (!policy) {
              result = make_error_tx_result(15, "policy set missing",
                                            "cannot activate missing policy",
                                            std::string{kExecuteCodespace});
              return;
            }
            auto active_key = make_active_policy_key(operation.scope);
            storage_.put(
                encoder,
                charter::schema::bytes_view_t{active_key.data(),
                                              active_key.size()},
                charter::schema::active_policy_pointer_t{
                    .policy_set_id = operation.policy_set_id,
                    .policy_set_version = operation.policy_set_version});
            result.info = "activate_policy_set persisted";
          },
          [&](const charter::schema::propose_intent_t& operation) {
            if (!workspace_exists(storage_, encoder, operation.workspace_id) ||
                !vault_exists(storage_, encoder, operation.workspace_id,
                              operation.vault_id)) {
              result = make_error_tx_result(16, "vault scope missing",
                                            "workspace/vault must exist",
                                            std::string{kExecuteCodespace});
              return;
            }
            auto scope = charter::schema::policy_scope_t{
                charter::schema::vault_t{.workspace_id = operation.workspace_id,
                                         .vault_id = operation.vault_id}};
            if (!active_policy_exists(storage_, encoder, scope)) {
              result = make_error_tx_result(17, "active policy missing",
                                            "activate a policy before intents",
                                            std::string{kExecuteCodespace});
              return;
            }
            auto intent_key =
                make_intent_key(operation.workspace_id, operation.vault_id,
                                operation.intent_id);
            auto existing =
                storage_.get<encoder_t, charter::schema::intent_state_t>(
                    encoder, charter::schema::bytes_view_t{intent_key.data(),
                                                           intent_key.size()});
            if (existing) {
              result = make_error_tx_result(19, "intent already exists",
                                            "intent_id already present",
                                            std::string{kExecuteCodespace});
              return;
            }
            auto requirements = resolve_policy_requirements(
                storage_, encoder, scope,
                operation_type_from_intent_action(operation.action));
            if (!requirements) {
              result = make_error_tx_result(20, "policy resolution failed",
                                            "active policy pointer is invalid",
                                            std::string{kExecuteCodespace});
              return;
            }
            std::visit(
                overloaded{
                    [&](const charter::schema::transfer_parameters_t& action) {
                      if (requirements->per_transaction_limit.has_value() &&
                          charter::schema::amount_t{action.amount} >
                              requirements->per_transaction_limit.value()) {
                        result = make_error_tx_result(
                            28, "limit exceeded",
                            "transfer amount exceeds per-transaction policy "
                            "limit",
                            std::string{kExecuteCodespace});
                        return;
                      }
                      if (requirements->require_whitelisted_destination &&
                          !destination_enabled(storage_, encoder,
                                               operation.workspace_id,
                                               action.destination_id)) {
                        result = make_error_tx_result(
                            29, "destination not whitelisted",
                            "destination must be enabled in whitelist",
                            std::string{kExecuteCodespace});
                        return;
                      }
                    }},
                operation.action);
            if (result.code != 0) {
              return;
            }
            if (!enforce_velocity_limits(
                    storage_, encoder, operation.workspace_id,
                    operation.vault_id, operation.action,
                    requirements->velocity_limits, current_block_time_ms_,
                    result, std::string{kExecuteCodespace})) {
              return;
            }
            auto now_ms = current_block_time_ms_;
            auto required_threshold = requirements->threshold;
            auto delay_ms = requirements->delay_ms;
            auto not_before = now_ms + delay_ms;
            auto status = charter::schema::intent_status_t::pending_approval;
            if (required_threshold == 0 && now_ms >= not_before) {
              status = charter::schema::intent_status_t::executable;
            }
            auto state = charter::schema::intent_state_t{
                .workspace_id = operation.workspace_id,
                .vault_id = operation.vault_id,
                .intent_id = operation.intent_id,
                .created_by = tx.signer,
                .created_at = now_ms,
                .not_before = not_before,
                .expires_at = operation.expires_at,
                .action = operation.action,
                .status = status,
                .policy_set_id = requirements->policy_set_id,
                .policy_version = requirements->policy_version,
                .required_threshold = required_threshold,
                .approvals_count = 0,
                .claim_requirements = requirements->claim_requirements};
            storage_.put(encoder,
                         charter::schema::bytes_view_t{intent_key.data(),
                                                       intent_key.size()},
                         state);
            result.info = "propose_intent persisted";
          },
          [&](const charter::schema::approve_intent_t& operation) {
            if (!workspace_exists(storage_, encoder, operation.workspace_id) ||
                !vault_exists(storage_, encoder, operation.workspace_id,
                              operation.vault_id)) {
              result = make_error_tx_result(16, "vault scope missing",
                                            "workspace/vault must exist",
                                            std::string{kExecuteCodespace});
              return;
            }
            auto intent_key =
                make_intent_key(operation.workspace_id, operation.vault_id,
                                operation.intent_id);
            auto intent =
                storage_.get<encoder_t, charter::schema::intent_state_t>(
                    encoder, charter::schema::bytes_view_t{intent_key.data(),
                                                           intent_key.size()});
            if (!intent) {
              result = make_error_tx_result(21, "intent missing",
                                            "intent must exist before approval",
                                            std::string{kExecuteCodespace});
              return;
            }
            if (intent->status == charter::schema::intent_status_t::executed ||
                intent->status == charter::schema::intent_status_t::cancelled) {
              result = make_error_tx_result(22, "intent not approvable",
                                            "intent already finalized",
                                            std::string{kExecuteCodespace});
              return;
            }
            auto now_ms = current_block_time_ms_;
            if (intent->expires_at.has_value() &&
                now_ms > intent->expires_at.value()) {
              intent->status = charter::schema::intent_status_t::expired;
              storage_.put(encoder,
                           charter::schema::bytes_view_t{intent_key.data(),
                                                         intent_key.size()},
                           *intent);
              result = make_error_tx_result(23, "intent expired",
                                            "intent can no longer be approved",
                                            std::string{kExecuteCodespace});
              return;
            }

            auto approval_key =
                make_approval_key(operation.intent_id, tx.signer);
            auto approval_existing =
                storage_.get<encoder_t, charter::schema::approval_state_t>(
                    encoder, charter::schema::bytes_view_t{
                                 approval_key.data(), approval_key.size()});
            if (approval_existing) {
              result =
                  make_error_tx_result(24, "duplicate approval",
                                       "signer already approved this intent",
                                       std::string{kExecuteCodespace});
              return;
            }
            auto scope = charter::schema::policy_scope_t{
                charter::schema::vault_t{.workspace_id = operation.workspace_id,
                                         .vault_id = operation.vault_id}};
            auto requirements = resolve_policy_requirements(
                storage_, encoder, scope,
                operation_type_from_intent_action(intent->action));
            if (!requirements) {
              result = make_error_tx_result(20, "policy resolution failed",
                                            "active policy pointer is invalid",
                                            std::string{kExecuteCodespace});
              return;
            }
            if (requirements->require_distinct_from_initiator &&
                signer_ids_equal(intent->created_by, tx.signer)) {
              result = make_error_tx_result(
                  35, "separation of duties violated",
                  "approver must be distinct from intent initiator",
                  std::string{kExecuteCodespace});
              return;
            }
            storage_.put(encoder,
                         charter::schema::bytes_view_t{approval_key.data(),
                                                       approval_key.size()},
                         charter::schema::approval_state_t{
                             .intent_id = operation.intent_id,
                             .signer = tx.signer,
                             .signed_at = now_ms});

            intent->approvals_count += 1;
            if (intent->approvals_count >= intent->required_threshold &&
                now_ms >= intent->not_before) {
              intent->status = charter::schema::intent_status_t::executable;
            } else {
              intent->status =
                  charter::schema::intent_status_t::pending_approval;
            }
            storage_.put(encoder,
                         charter::schema::bytes_view_t{intent_key.data(),
                                                       intent_key.size()},
                         *intent);
            result.info = "approve_intent persisted";
          },
          [&](const charter::schema::cancel_intent_t& operation) {
            if (!workspace_exists(storage_, encoder, operation.workspace_id) ||
                !vault_exists(storage_, encoder, operation.workspace_id,
                              operation.vault_id)) {
              result = make_error_tx_result(16, "vault scope missing",
                                            "workspace/vault must exist",
                                            std::string{kExecuteCodespace});
              return;
            }
            auto intent_key =
                make_intent_key(operation.workspace_id, operation.vault_id,
                                operation.intent_id);
            auto intent =
                storage_.get<encoder_t, charter::schema::intent_state_t>(
                    encoder, charter::schema::bytes_view_t{intent_key.data(),
                                                           intent_key.size()});
            if (!intent) {
              result = make_error_tx_result(21, "intent missing",
                                            "intent must exist before cancel",
                                            std::string{kExecuteCodespace});
              return;
            }
            if (intent->status == charter::schema::intent_status_t::executed) {
              result =
                  make_error_tx_result(25, "intent already executed",
                                       "executed intent cannot be cancelled",
                                       std::string{kExecuteCodespace});
              return;
            }
            intent->status = charter::schema::intent_status_t::cancelled;
            storage_.put(encoder,
                         charter::schema::bytes_view_t{intent_key.data(),
                                                       intent_key.size()},
                         *intent);
            result.info = "cancel_intent persisted";
          },
          [&](const charter::schema::execute_intent_t& operation) {
            if (!workspace_exists(storage_, encoder, operation.workspace_id) ||
                !vault_exists(storage_, encoder, operation.workspace_id,
                              operation.vault_id)) {
              result = make_error_tx_result(16, "vault scope missing",
                                            "workspace/vault must exist",
                                            std::string{kExecuteCodespace});
              return;
            }
            auto intent_key =
                make_intent_key(operation.workspace_id, operation.vault_id,
                                operation.intent_id);
            auto intent =
                storage_.get<encoder_t, charter::schema::intent_state_t>(
                    encoder, charter::schema::bytes_view_t{intent_key.data(),
                                                           intent_key.size()});
            if (!intent) {
              result = make_error_tx_result(
                  21, "intent missing", "intent must exist before execution",
                  std::string{kExecuteCodespace});
              return;
            }
            auto now_ms = current_block_time_ms_;
            if (intent->expires_at.has_value() &&
                now_ms > intent->expires_at.value()) {
              intent->status = charter::schema::intent_status_t::expired;
              storage_.put(encoder,
                           charter::schema::bytes_view_t{intent_key.data(),
                                                         intent_key.size()},
                           *intent);
              result = make_error_tx_result(23, "intent expired",
                                            "intent can no longer be executed",
                                            std::string{kExecuteCodespace});
              return;
            }
            if (intent->approvals_count < intent->required_threshold ||
                now_ms < intent->not_before) {
              result = make_error_tx_result(
                  26, "intent not executable",
                  "threshold/timelock requirements not met",
                  std::string{kExecuteCodespace});
              return;
            }
            auto scope = charter::schema::policy_scope_t{
                charter::schema::vault_t{.workspace_id = operation.workspace_id,
                                         .vault_id = operation.vault_id}};
            auto requirements = resolve_policy_requirements(
                storage_, encoder, scope,
                operation_type_from_intent_action(intent->action));
            if (!requirements) {
              result = make_error_tx_result(20, "policy resolution failed",
                                            "active policy pointer is invalid",
                                            std::string{kExecuteCodespace});
              return;
            }
            if (requirements->require_distinct_from_executor) {
              auto executor_approval_key =
                  make_approval_key(operation.intent_id, tx.signer);
              auto approval_by_executor =
                  storage_.get<encoder_t, charter::schema::approval_state_t>(
                      encoder, charter::schema::bytes_view_t{
                                   executor_approval_key.data(),
                                   executor_approval_key.size()});
              if (approval_by_executor.has_value()) {
                result = make_error_tx_result(
                    35, "separation of duties violated",
                    "executor must be distinct from approvers for this intent",
                    std::string{kExecuteCodespace});
                return;
              }
            }
            if (!enforce_velocity_limits(
                    storage_, encoder, operation.workspace_id,
                    operation.vault_id, intent->action,
                    requirements->velocity_limits, now_ms, result,
                    std::string{kExecuteCodespace})) {
              return;
            }
            for (const auto& requirement : intent->claim_requirements) {
              if (!attestation_satisfies_requirement(
                      storage_, encoder, intent->workspace_id,
                      intent->workspace_id, requirement, now_ms)) {
                result = make_error_tx_result(
                    30, "claim requirement unsatisfied",
                    "required attestation claim is missing or expired",
                    std::string{kExecuteCodespace});
                return;
              }
            }
            intent->status = charter::schema::intent_status_t::executed;
            storage_.put(encoder,
                         charter::schema::bytes_view_t{intent_key.data(),
                                                       intent_key.size()},
                         *intent);
            apply_velocity_limits(storage_, encoder, operation.workspace_id,
                                  operation.vault_id, intent->action,
                                  requirements->velocity_limits, now_ms);
            result.info = "execute_intent persisted";
          },
          [&](const charter::schema::upsert_attestation_t& operation) {
            if (!workspace_exists(storage_, encoder, operation.workspace_id)) {
              result = make_error_tx_result(18, "workspace missing",
                                            "workspace must exist",
                                            std::string{kExecuteCodespace});
              return;
            }
            auto attestation_key =
                make_attestation_key(operation.workspace_id, operation.subject,
                                     operation.claim, operation.issuer);
            auto now_ms = current_block_time_ms_;
            storage_.put(
                encoder,
                charter::schema::bytes_view_t{attestation_key.data(),
                                              attestation_key.size()},
                charter::schema::attestation_record_t{
                    .workspace_id = operation.workspace_id,
                    .subject = operation.subject,
                    .claim = operation.claim,
                    .issuer = operation.issuer,
                    .issued_at = now_ms,
                    .expires_at = operation.expires_at,
                    .status = charter::schema::attestation_status_t::active,
                    .reference_hash = operation.reference_hash});
            result.info = "upsert_attestation persisted";
          },
          [&](const charter::schema::revoke_attestation_t& operation) {
            if (!workspace_exists(storage_, encoder, operation.workspace_id)) {
              result = make_error_tx_result(18, "workspace missing",
                                            "workspace must exist",
                                            std::string{kExecuteCodespace});
              return;
            }
            auto attestation_key =
                make_attestation_key(operation.workspace_id, operation.subject,
                                     operation.claim, operation.issuer);
            auto record =
                storage_.get<encoder_t, charter::schema::attestation_record_t>(
                    encoder,
                    charter::schema::bytes_view_t{attestation_key.data(),
                                                  attestation_key.size()});
            if (!record) {
              result = make_error_tx_result(27, "attestation missing",
                                            "attestation not found",
                                            std::string{kExecuteCodespace});
              return;
            }
            record->status = charter::schema::attestation_status_t::revoked;
            storage_.put(encoder,
                         charter::schema::bytes_view_t{attestation_key.data(),
                                                       attestation_key.size()},
                         *record);
            result.info = "revoke_attestation persisted";
          },
          [&](const charter::schema::propose_destination_update_t& operation) {
            if (!workspace_exists(storage_, encoder, operation.workspace_id)) {
              result = make_error_tx_result(
                  11, "workspace missing",
                  "workspace must exist before destination update",
                  std::string{kExecuteCodespace});
              return;
            }
            auto update_key = make_destination_update_key(
                operation.workspace_id, operation.destination_id,
                operation.update_id);
            auto existing =
                storage_.get<encoder_t,
                             charter::schema::destination_update_state_t>(
                    encoder, charter::schema::bytes_view_t{update_key.data(),
                                                           update_key.size()});
            if (existing.has_value()) {
              result =
                  make_error_tx_result(36, "destination update exists",
                                       "destination update id already present",
                                       std::string{kExecuteCodespace});
              return;
            }
            auto now_ms = current_block_time_ms_;
            auto state = charter::schema::destination_update_state_t{
                .workspace_id = operation.workspace_id,
                .destination_id = operation.destination_id,
                .update_id = operation.update_id,
                .type = operation.type,
                .chain_type = operation.chain_type,
                .address_or_contract = operation.address_or_contract,
                .enabled = operation.enabled,
                .label = operation.label,
                .created_by = tx.signer,
                .created_at = now_ms,
                .not_before = now_ms + operation.delay_ms,
                .required_approvals =
                    std::max<uint32_t>(1, operation.required_approvals),
                .approvals_count = 0,
                .status = charter::schema::destination_update_status_t::
                    pending_approval};
            storage_.put(encoder,
                         charter::schema::bytes_view_t{update_key.data(),
                                                       update_key.size()},
                         state);
            result.info = "propose_destination_update persisted";
          },
          [&](const charter::schema::approve_destination_update_t& operation) {
            auto update_key = make_destination_update_key(
                operation.workspace_id, operation.destination_id,
                operation.update_id);
            auto update =
                storage_.get<encoder_t,
                             charter::schema::destination_update_state_t>(
                    encoder, charter::schema::bytes_view_t{update_key.data(),
                                                           update_key.size()});
            if (!update.has_value()) {
              result = make_error_tx_result(
                  37, "destination update missing",
                  "destination update must exist before approval",
                  std::string{kExecuteCodespace});
              return;
            }
            if (update->status ==
                charter::schema::destination_update_status_t::applied) {
              result =
                  make_error_tx_result(38, "destination update finalized",
                                       "destination update already applied",
                                       std::string{kExecuteCodespace});
              return;
            }
            auto approval_key =
                make_approval_key(operation.update_id, tx.signer);
            auto approval_existing =
                storage_.get<encoder_t, charter::schema::approval_state_t>(
                    encoder, charter::schema::bytes_view_t{
                                 approval_key.data(), approval_key.size()});
            if (approval_existing) {
              result = make_error_tx_result(
                  24, "duplicate approval",
                  "signer already approved this destination update",
                  std::string{kExecuteCodespace});
              return;
            }
            storage_.put(encoder,
                         charter::schema::bytes_view_t{approval_key.data(),
                                                       approval_key.size()},
                         charter::schema::approval_state_t{
                             .intent_id = operation.update_id,
                             .signer = tx.signer,
                             .signed_at = current_block_time_ms_});
            update->approvals_count += 1;
            if (update->approvals_count >= update->required_approvals &&
                current_block_time_ms_ >= update->not_before) {
              update->status =
                  charter::schema::destination_update_status_t::executable;
            }
            storage_.put(encoder,
                         charter::schema::bytes_view_t{update_key.data(),
                                                       update_key.size()},
                         *update);
            result.info = "approve_destination_update persisted";
          },
          [&](const charter::schema::apply_destination_update_t& operation) {
            auto update_key = make_destination_update_key(
                operation.workspace_id, operation.destination_id,
                operation.update_id);
            auto update =
                storage_.get<encoder_t,
                             charter::schema::destination_update_state_t>(
                    encoder, charter::schema::bytes_view_t{update_key.data(),
                                                           update_key.size()});
            if (!update.has_value()) {
              result = make_error_tx_result(
                  37, "destination update missing",
                  "destination update must exist before apply",
                  std::string{kExecuteCodespace});
              return;
            }
            if (update->approvals_count < update->required_approvals ||
                current_block_time_ms_ < update->not_before) {
              result = make_error_tx_result(
                  39, "destination update not executable",
                  "destination update threshold/timelock requirements not met",
                  std::string{kExecuteCodespace});
              return;
            }
            auto destination_key = make_destination_key(
                operation.workspace_id, operation.destination_id);
            storage_.put(encoder,
                         charter::schema::bytes_view_t{destination_key.data(),
                                                       destination_key.size()},
                         charter::schema::destination_state_t{
                             .workspace_id = update->workspace_id,
                             .destination_id = update->destination_id,
                             .type = update->type,
                             .chain_type = update->chain_type,
                             .address_or_contract = update->address_or_contract,
                             .enabled = update->enabled,
                             .label = update->label});
            update->status =
                charter::schema::destination_update_status_t::applied;
            storage_.put(encoder,
                         charter::schema::bytes_view_t{update_key.data(),
                                                       update_key.size()},
                         *update);
            result.info = "apply_destination_update persisted";
          },
          [&](const charter::schema::upsert_role_assignment_t& operation) {
            auto role_assignment_key = make_role_assignment_key(
                operation.scope, operation.subject, operation.role);
            storage_.put(
                encoder,
                charter::schema::bytes_view_t{role_assignment_key.data(),
                                              role_assignment_key.size()},
                charter::schema::role_assignment_state_t{operation});
            append_security_event(
                storage_, encoder,
                charter::schema::security_event_type_t::role_assignment_updated,
                charter::schema::security_event_severity_t::info, 0,
                "role assignment updated", tx.signer, std::nullopt,
                std::nullopt, current_block_time_ms_, current_block_height_);
            result.info = "upsert_role_assignment persisted";
          },
          [&](const charter::schema::upsert_signer_quarantine_t& operation) {
            auto quarantine_key = make_signer_quarantine_key(operation.signer);
            storage_.put(encoder,
                         charter::schema::bytes_view_t{quarantine_key.data(),
                                                       quarantine_key.size()},
                         charter::schema::signer_quarantine_state_t{operation});
            append_security_event(
                storage_, encoder,
                charter::schema::security_event_type_t::
                    signer_quarantine_updated,
                charter::schema::security_event_severity_t::warning, 0,
                "signer quarantine updated", tx.signer, std::nullopt,
                std::nullopt, current_block_time_ms_, current_block_height_);
            result.info = "upsert_signer_quarantine persisted";
          },
          [&](const charter::schema::set_degraded_mode_t& operation) {
            auto mode_key = make_degraded_mode_key();
            storage_.put(
                encoder,
                charter::schema::bytes_view_t{mode_key.data(), mode_key.size()},
                charter::schema::degraded_mode_state_t{operation});
            append_security_event(
                storage_, encoder,
                charter::schema::security_event_type_t::degraded_mode_updated,
                charter::schema::security_event_severity_t::warning, 0,
                "degraded mode updated", tx.signer, std::nullopt, std::nullopt,
                current_block_time_ms_, current_block_height_);
            result.info = "set_degraded_mode persisted";
          }},
      tx.payload);

  auto payload_scope = scope_from_payload(tx.payload);
  auto workspace_id = std::optional<charter::schema::hash32_t>{};
  auto vault_id = std::optional<charter::schema::hash32_t>{};
  if (payload_scope.has_value()) {
    std::visit(overloaded{[&](const charter::schema::workspace_scope_t& scope) {
                            workspace_id = scope.workspace_id;
                          },
                          [&](const charter::schema::vault_t& scope) {
                            workspace_id = scope.workspace_id;
                            vault_id = scope.vault_id;
                          }},
               payload_scope.value());
  }
  if (result.code != 0) {
    append_security_event(
        storage_, encoder, event_type_for_tx_error(result.code, false),
        charter::schema::security_event_severity_t::error, result.code,
        result.log, tx.signer, workspace_id, vault_id, current_block_time_ms_,
        current_block_height_);
  }

  if (result.code == 0) {
    result.gas_wanted = 1000;
    result.gas_used = 750;
  }
  return result;
}

tx_result engine::validate_tx(const charter::schema::transaction_t& tx,
                              std::string_view codespace,
                              std::optional<uint64_t> expected_nonce) {
  auto encoder = encoder_t{};
  auto degraded_mode = current_degraded_mode(storage_, encoder);
  if (degraded_mode != charter::schema::degraded_mode_t::normal &&
      !std::holds_alternative<charter::schema::set_degraded_mode_t>(
          tx.payload)) {
    return make_error_tx_result(32, "degraded mode active",
                                "only degraded mode updates are allowed",
                                std::string{codespace});
  }
  if (signer_quarantined(storage_, encoder, tx.signer,
                         current_block_time_ms_)) {
    return make_error_tx_result(31, "signer quarantined",
                                "signer is blocked by quarantine policy",
                                std::string{codespace});
  }
  auto required_roles = required_roles_for_payload(tx.payload);
  if (!required_roles.empty()) {
    auto scope = scope_from_payload(tx.payload);
    auto authorized = false;
    if (scope.has_value()) {
      for (const auto role : required_roles) {
        if (signer_has_role_for_scope(storage_, encoder, scope.value(),
                                      tx.signer, role,
                                      current_block_time_ms_)) {
          authorized = true;
          break;
        }
      }
    } else {
      authorized = signer_has_required_global_role(
          storage_, encoder, tx.signer, required_roles, current_block_time_ms_);
    }
    if (!authorized) {
      return make_error_tx_result(33, "authorization denied",
                                  "signer lacks required role for operation",
                                  std::string{codespace});
    }
  }

  if (tx.version != 1) {
    return make_error_tx_result(2, "unsupported transaction version",
                                "expected version 1", std::string{codespace});
  }
  if (tx.chain_id != chain_id_) {
    return make_error_tx_result(
        3, "invalid chain id",
        "transaction chain_id does not match app chain_id",
        std::string{codespace});
  }
  if (!signer_signature_compatible(tx.signer, tx.signature)) {
    return make_error_tx_result(
        5, "invalid signature type",
        "signer_id and signature variant are incompatible",
        std::string{codespace});
  }
  auto signing_bytes = make_signing_bytes(tx);
  if (signature_verifier_ &&
      !signature_verifier_(charter::schema::bytes_view_t{signing_bytes.data(),
                                                         signing_bytes.size()},
                           tx.signer, tx.signature)) {
    return make_error_tx_result(
        6, "signature verification failed",
        "signature verifier rejected transaction signature",
        std::string{codespace});
  }

  auto nonce_to_match = uint64_t{};
  if (expected_nonce.has_value()) {
    nonce_to_match = expected_nonce.value();
  } else {
    auto nonce_key = make_nonce_key(tx.signer);
    auto stored_nonce = storage_.get<encoder_t, uint64_t>(
        encoder,
        charter::schema::bytes_view_t{nonce_key.data(), nonce_key.size()});
    nonce_to_match = stored_nonce.value_or(0) + 1;
  }

  if (tx.nonce != nonce_to_match) {
    return make_error_tx_result(
        4, "invalid nonce", "expected nonce " + std::to_string(nonce_to_match),
        std::string{codespace});
  }

  return tx_result{};
}

block_result engine::finalize_block(
    uint64_t height,
    const std::vector<charter::schema::bytes_t>& txs) {
  auto lock = std::scoped_lock{mutex_};
  auto result = block_result{};
  result.tx_results.reserve(txs.size());
  current_block_time_ms_ = height * 1000;
  current_block_height_ = height;

  auto rolling_hash = last_committed_state_root_;
  auto expected_nonces = std::map<std::string, uint64_t>{};
  for (size_t i = 0; i < txs.size(); ++i) {
    auto decode_error = std::string{};
    auto maybe_tx = decode_transaction(
        charter::schema::bytes_view_t{txs[i].data(), txs[i].size()},
        decode_error);
    if (!maybe_tx) {
      auto tx_result = make_error_tx_result(1, "invalid transaction",
                                            decode_error, "charter.finalize");
      auto history_key = make_history_key(height, static_cast<uint32_t>(i));
      auto encoder = encoder_t{};
      storage_.put(
          encoder,
          charter::schema::bytes_view_t{history_key.data(), history_key.size()},
          std::tuple{tx_result.code, txs[i]});
      append_security_event(
          storage_, encoder, event_type_for_tx_error(tx_result.code, true),
          charter::schema::security_event_severity_t::error, tx_result.code,
          tx_result.log, std::nullopt, std::nullopt, std::nullopt,
          current_block_time_ms_, current_block_height_);
      append_tx_result_event(tx_result, height, static_cast<uint32_t>(i),
                             std::nullopt);
      result.tx_results.push_back(std::move(tx_result));
      continue;
    }
    auto signer_key = make_signer_cache_key(maybe_tx->signer);
    auto expected_nonce = std::optional<uint64_t>{};
    if (auto it = expected_nonces.find(signer_key);
        it != std::end(expected_nonces)) {
      expected_nonce = it->second;
    }
    auto validation =
        validate_tx(*maybe_tx, "charter.finalize", expected_nonce);
    if (validation.code != 0) {
      auto history_key = make_history_key(height, static_cast<uint32_t>(i));
      auto encoder = encoder_t{};
      storage_.put(
          encoder,
          charter::schema::bytes_view_t{history_key.data(), history_key.size()},
          std::tuple{validation.code, txs[i]});
      append_security_event(
          storage_, encoder, event_type_for_tx_error(validation.code, true),
          charter::schema::security_event_severity_t::error, validation.code,
          validation.log, maybe_tx->signer, std::nullopt, std::nullopt,
          current_block_time_ms_, current_block_height_);
      append_tx_result_event(validation, height, static_cast<uint32_t>(i),
                             maybe_tx);
      result.tx_results.push_back(std::move(validation));
      continue;
    }

    auto tx_result = execute_operation(*maybe_tx);
    auto history_key = make_history_key(height, static_cast<uint32_t>(i));
    auto encoder = encoder_t{};
    storage_.put(
        encoder,
        charter::schema::bytes_view_t{history_key.data(), history_key.size()},
        std::tuple{tx_result.code, txs[i]});
    append_tx_result_event(tx_result, height, static_cast<uint32_t>(i),
                           maybe_tx);
    result.tx_results.push_back(std::move(tx_result));
    if (tx_result.code == 0) {
      auto nonce_key = make_nonce_key(maybe_tx->signer);
      storage_.put(
          encoder,
          charter::schema::bytes_view_t{nonce_key.data(), nonce_key.size()},
          maybe_tx->nonce);
      expected_nonces[signer_key] = maybe_tx->nonce + 1;
      rolling_hash = fold_app_hash(rolling_hash, txs[i], height, i);
    }
  }

  pending_height_ = static_cast<int64_t>(height);
  pending_state_root_ = rolling_hash;
  result.state_root = rolling_hash;
  return result;
}

commit_result engine::commit() {
  auto lock = std::scoped_lock{mutex_};
  if (pending_height_ > 0) {
    last_committed_height_ = pending_height_;
    last_committed_state_root_ = pending_state_root_;
    pending_height_ = 0;
  }

  create_snapshot_if_due(last_committed_height_);
  storage_.save_committed_state(charter::storage::committed_state{
      .height = last_committed_height_, .state_root = last_committed_state_root_});

  auto result = commit_result{};
  result.retain_height = 0;
  result.committed_height = last_committed_height_;
  result.state_root = last_committed_state_root_;
  return result;
}

app_info engine::info() const {
  auto lock = std::scoped_lock{mutex_};
  auto result = app_info{};
  result.last_block_height = last_committed_height_;
  result.last_block_state_root = last_committed_state_root_;
  return result;
}

query_result engine::query(std::string_view path,
                           const charter::schema::bytes_view_t& data) {
  auto lock = std::scoped_lock{mutex_};
  auto encoder = encoder_t{};
  auto result = query_result{};
  result.height = last_committed_height_;
  result.codespace = std::string{kQueryCodespace};
  result.key = charter::schema::make_bytes(data);
  auto query_error = [&](uint32_t code, std::string log, std::string info) {
    return make_error_query_result(code, std::move(log), std::move(info),
                                   std::string{kQueryCodespace},
                                   last_committed_height_, data);
  };

  if (path == "/engine/info") {
    result.value = encoder.encode(std::tuple{
        last_committed_height_, last_committed_state_root_, chain_id_});
    return result;
  }

  if (path == "/engine/keyspaces") {
    auto prefixes = std::vector<std::string>{};
    prefixes.reserve(kEngineKeyspaces.size());
    for (const auto& prefix : kEngineKeyspaces) {
      prefixes.emplace_back(prefix);
    }
    result.value = encoder.encode(prefixes);
    return result;
  }

  if (path == "/state/workspace") {
    if (data.size() != 32) {
      return query_error(1, "invalid key size",
                         "workspace query key must be 32 bytes");
    }
    auto workspace_id = charter::schema::hash32_t{};
    std::copy_n(std::begin(data), workspace_id.size(),
                std::begin(workspace_id));
    auto key = make_workspace_key(workspace_id);
    auto workspace =
        storage_.get<encoder_t, charter::schema::workspace_state_t>(
            encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    if (!workspace) {
      return query_error(2, "not found", "workspace not found");
    }
    result.value = encoder.encode(*workspace);
    return result;
  }

  if (path == "/state/vault") {
    auto decoded = encoder.try_decode<
        std::tuple<charter::schema::hash32_t, charter::schema::hash32_t>>(data);
    if (!decoded) {
      return query_error(
          1, "invalid key encoding",
          "vault query key must decode to (workspace_id,vault_id)");
    }
    auto workspace_id = std::get<0>(decoded.value());
    auto vault_id = std::get<1>(decoded.value());
    auto key = make_vault_key(workspace_id, vault_id);
    auto vault = storage_.get<encoder_t, charter::schema::vault_state_t>(
        encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    if (!vault) {
      return query_error(2, "not found", "vault not found");
    }
    result.value = encoder.encode(*vault);
    return result;
  }

  if (path == "/state/destination") {
    auto decoded = encoder.try_decode<
        std::tuple<charter::schema::hash32_t, charter::schema::hash32_t>>(data);
    if (!decoded) {
      return query_error(
          1, "invalid key encoding",
          "destination query key must decode to (workspace_id,destination_id)");
    }
    auto key = make_destination_key(std::get<0>(decoded.value()),
                                    std::get<1>(decoded.value()));
    auto destination =
        storage_.get<encoder_t, charter::schema::destination_state_t>(
            encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    if (!destination) {
      return query_error(2, "not found", "destination not found");
    }
    result.value = encoder.encode(*destination);
    return result;
  }

  if (path == "/state/policy_set") {
    auto decoded =
        encoder.try_decode<std::tuple<charter::schema::hash32_t, uint32_t>>(
            data);
    if (!decoded) {
      return query_error(
          1, "invalid key encoding",
          "policy_set query key must decode to (policy_set_id,policy_version)");
    }
    auto key = make_policy_set_key(std::get<0>(decoded.value()),
                                   std::get<1>(decoded.value()));
    auto policy = storage_.get<encoder_t, charter::schema::policy_set_state_t>(
        encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    if (!policy) {
      return query_error(2, "not found", "policy set not found");
    }
    result.value = encoder.encode(*policy);
    return result;
  }

  if (path == "/state/active_policy") {
    auto decoded = encoder.try_decode<charter::schema::policy_scope_t>(data);
    if (!decoded) {
      return query_error(1, "invalid key encoding",
                         "active_policy query key must decode to policy_scope");
    }
    auto key = make_active_policy_key(decoded.value());
    auto active =
        storage_.get<encoder_t, charter::schema::active_policy_pointer_t>(
            encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    if (!active) {
      return query_error(2, "not found", "active policy not found");
    }
    result.value = encoder.encode(*active);
    return result;
  }

  if (path == "/state/intent") {
    auto decoded = encoder.try_decode<
        std::tuple<charter::schema::hash32_t, charter::schema::hash32_t,
                   charter::schema::hash32_t>>(data);
    if (!decoded) {
      return query_error(
          1, "invalid key encoding",
          "intent query key must decode to (workspace_id,vault_id,intent_id)");
    }
    auto key = make_intent_key(std::get<0>(decoded.value()),
                               std::get<1>(decoded.value()),
                               std::get<2>(decoded.value()));
    auto intent = storage_.get<encoder_t, charter::schema::intent_state_t>(
        encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    if (!intent) {
      return query_error(2, "not found", "intent not found");
    }
    result.value = encoder.encode(*intent);
    return result;
  }

  if (path == "/state/approval") {
    auto decoded = encoder.try_decode<
        std::tuple<charter::schema::hash32_t, charter::schema::signer_id_t>>(
        data);
    if (!decoded) {
      return query_error(
          1, "invalid key encoding",
          "approval query key must decode to (intent_id,signer)");
    }
    auto key = make_approval_key(std::get<0>(decoded.value()),
                                 std::get<1>(decoded.value()));
    auto approval = storage_.get<encoder_t, charter::schema::approval_state_t>(
        encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    if (!approval) {
      return query_error(2, "not found", "approval not found");
    }
    result.value = encoder.encode(*approval);
    return result;
  }

  if (path == "/state/attestation") {
    auto decoded = encoder.try_decode<std::tuple<
        charter::schema::hash32_t, charter::schema::hash32_t,
        charter::schema::claim_type_t, charter::schema::signer_id_t>>(data);
    if (!decoded) {
      return query_error(1, "invalid key encoding",
                         "attestation query key must decode to "
                         "(workspace_id,subject,claim,issuer)");
    }
    auto key = make_attestation_key(
        std::get<0>(decoded.value()), std::get<1>(decoded.value()),
        std::get<2>(decoded.value()), std::get<3>(decoded.value()));
    auto record =
        storage_.get<encoder_t, charter::schema::attestation_record_t>(
            encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    if (!record) {
      return query_error(2, "not found", "attestation not found");
    }
    result.value = encoder.encode(*record);
    return result;
  }

  if (path == "/state/role_assignment") {
    auto decoded = encoder.try_decode<
        std::tuple<charter::schema::policy_scope_t,
                   charter::schema::signer_id_t, charter::schema::role_id_t>>(
        data);
    if (!decoded) {
      return query_error(
          1, "invalid key encoding",
          "role_assignment query key must decode to (scope,subject,role)");
    }
    auto key = make_role_assignment_key(std::get<0>(decoded.value()),
                                        std::get<1>(decoded.value()),
                                        std::get<2>(decoded.value()));
    auto role_assignment =
        storage_.get<encoder_t, charter::schema::role_assignment_state_t>(
            encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    if (!role_assignment) {
      return query_error(2, "not found", "role assignment not found");
    }
    result.value = encoder.encode(*role_assignment);
    return result;
  }

  if (path == "/state/signer_quarantine") {
    auto decoded = encoder.try_decode<charter::schema::signer_id_t>(data);
    if (!decoded) {
      return query_error(
          1, "invalid key encoding",
          "signer_quarantine query key must decode to signer_id_t");
    }
    auto key = make_signer_quarantine_key(decoded.value());
    auto quarantine =
        storage_.get<encoder_t, charter::schema::signer_quarantine_state_t>(
            encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    if (!quarantine) {
      return query_error(2, "not found", "signer quarantine not found");
    }
    result.value = encoder.encode(*quarantine);
    return result;
  }

  if (path == "/state/degraded_mode") {
    auto mode = load_degraded_mode_state(storage_, encoder);
    if (!mode) {
      result.value = encoder.encode(charter::schema::degraded_mode_state_t{});
      return result;
    }
    result.value = encoder.encode(*mode);
    return result;
  }

  if (path == "/state/destination_update") {
    auto decoded = encoder.try_decode<
        std::tuple<charter::schema::hash32_t, charter::schema::hash32_t,
                   charter::schema::hash32_t>>(data);
    if (!decoded) {
      return query_error(1, "invalid key encoding",
                         "destination_update key must decode to "
                         "(workspace_id,destination_id,update_id)");
    }
    auto key = make_destination_update_key(std::get<0>(decoded.value()),
                                           std::get<1>(decoded.value()),
                                           std::get<2>(decoded.value()));
    auto update =
        storage_.get<encoder_t, charter::schema::destination_update_state_t>(
            encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    if (!update) {
      return query_error(2, "not found", "destination update not found");
    }
    result.value = encoder.encode(*update);
    return result;
  }

  if (path == "/history/range") {
    auto decoded = encoder.try_decode<std::tuple<uint64_t, uint64_t>>(data);
    if (!decoded) {
      return query_error(
          1, "invalid key encoding",
          "history range query requires SCALE tuple(from_height,to_height)");
    }
    auto from_height = std::get<0>(decoded.value());
    auto to_height = std::get<1>(decoded.value());
    auto prefix = charter::schema::make_bytes(kHistoryPrefix);
    auto history_rows = storage_.list_by_prefix(
        charter::schema::bytes_view_t{prefix.data(), prefix.size()});
    auto encoded_rows = std::vector<
        std::tuple<uint64_t, uint32_t, uint32_t, charter::schema::bytes_t>>{};
    for (const auto& [key, value] : history_rows) {
      auto parsed = parse_history_key(
          charter::schema::bytes_view_t{key.data(), key.size()});
      if (!parsed) {
        continue;
      }
      auto [height, index] = *parsed;
      if (height < from_height || height > to_height) {
        continue;
      }
      auto decoded_row =
          encoder.try_decode<std::tuple<uint32_t, charter::schema::bytes_t>>(
              charter::schema::bytes_view_t{value.data(), value.size()});
      if (!decoded_row) {
        continue;
      }
      encoded_rows.push_back(std::tuple{height, index,
                                        std::get<0>(decoded_row.value()),
                                        std::get<1>(decoded_row.value())});
    }
    result.value = encoder.encode(encoded_rows);
    return result;
  }

  if (path == "/history/export") {
    auto state_prefix = charter::schema::make_bytes(kStatePrefix);
    auto history_prefix = charter::schema::make_bytes(kHistoryPrefix);
    auto snapshot_prefix = charter::schema::make_bytes(kSnapshotPrefix);
    auto state = storage_.list_by_prefix(charter::schema::bytes_view_t{
        state_prefix.data(), state_prefix.size()});
    auto history_rows = storage_.list_by_prefix(charter::schema::bytes_view_t{
        history_prefix.data(), history_prefix.size()});
    auto snapshots = storage_.list_by_prefix(charter::schema::bytes_view_t{
        snapshot_prefix.data(), snapshot_prefix.size()});
    auto committed = storage_.load_committed_state();
    result.value = encoder.encode(std::tuple{
        uint16_t{1}, committed, state, history_rows, snapshots, chain_id_});
    return result;
  }

  if (path == "/events/range") {
    auto decoded = encoder.try_decode<std::tuple<uint64_t, uint64_t>>(data);
    if (!decoded) {
      return query_error(
          1, "invalid key encoding",
          "events range query requires SCALE tuple(from_id,to_id)");
    }
    auto from_id = std::get<0>(decoded.value());
    auto to_id = std::get<1>(decoded.value());
    auto prefix = charter::schema::make_bytes(kEventPrefix);
    auto rows = storage_.list_by_prefix(
        charter::schema::bytes_view_t{prefix.data(), prefix.size()});
    auto events = std::vector<charter::schema::security_event_record_t>{};
    for (const auto& [key, value] : rows) {
      auto parsed = parse_event_key(
          charter::schema::bytes_view_t{key.data(), key.size()});
      if (!parsed.has_value() || parsed.value() < from_id ||
          parsed.value() > to_id) {
        continue;
      }
      auto event = encoder.try_decode<charter::schema::security_event_record_t>(
          charter::schema::bytes_view_t{value.data(), value.size()});
      if (event.has_value()) {
        events.push_back(event.value());
      }
    }
    result.value = encoder.encode(events);
    return result;
  }

  return query_error(
      3, "unsupported path",
      "supported paths: /engine/info, /state/workspace, /state/vault, "
      "/state/destination, /state/policy_set, /state/active_policy, "
      "/state/intent, /state/approval, /state/attestation, "
      "/state/role_assignment, "
      "/state/signer_quarantine, /state/degraded_mode, "
      "/state/destination_update, "
      "/history/range, /history/export, /events/range, /engine/keyspaces");
}

std::vector<history_entry> engine::history(uint64_t from_height,
                                           uint64_t to_height) const {
  auto lock = std::scoped_lock{mutex_};
  auto prefix = charter::schema::make_bytes(kHistoryPrefix);
  auto rows = storage_.list_by_prefix(
      charter::schema::bytes_view_t{prefix.data(), prefix.size()});
  auto output = std::vector<history_entry>{};
  auto encoder = encoder_t{};
  for (const auto& [key, value] : rows) {
    auto parsed = parse_history_key(
        charter::schema::bytes_view_t{key.data(), key.size()});
    if (!parsed) {
      continue;
    }
    auto [height, index] = *parsed;
    if (height < from_height || height > to_height) {
      continue;
    }
    auto decoded =
        encoder.try_decode<std::tuple<uint32_t, charter::schema::bytes_t>>(
            charter::schema::bytes_view_t{value.data(), value.size()});
    if (!decoded) {
      continue;
    }
    output.push_back(history_entry{.height = height,
                                   .index = index,
                                   .code = std::get<0>(decoded.value()),
                                   .tx = std::get<1>(decoded.value())});
  }
  return output;
}

bool engine::export_backup(std::string_view backup_path) const {
  if (backup_path.empty()) {
    return false;
  }
  auto backup = export_backup();
  auto output =
      std::ofstream{backup_path.data(), std::ios::binary | std::ios::trunc};
  if (!output.good()) {
    spdlog::error("Failed opening backup output '{}'", backup_path);
    return false;
  }
  output.write(reinterpret_cast<const char*>(backup.data()), backup.size());
  if (!output.good()) {
    spdlog::error("Failed writing backup output '{}'", backup_path);
    return false;
  }
  spdlog::info("Persisted backup to '{}'", backup_path);
  return true;
}

charter::schema::bytes_t engine::export_backup() const {
  auto lock = std::scoped_lock{mutex_};
  auto state_prefix = charter::schema::make_bytes(kStatePrefix);
  auto history_prefix = charter::schema::make_bytes(kHistoryPrefix);
  auto snapshot_prefix = charter::schema::make_bytes(kSnapshotPrefix);
  auto state = storage_.list_by_prefix(
      charter::schema::bytes_view_t{state_prefix.data(), state_prefix.size()});
  auto history_rows = storage_.list_by_prefix(charter::schema::bytes_view_t{
      history_prefix.data(), history_prefix.size()});
  auto snapshots = storage_.list_by_prefix(charter::schema::bytes_view_t{
      snapshot_prefix.data(), snapshot_prefix.size()});
  auto committed = storage_.load_committed_state();

  auto encoder = encoder_t{};
  return encoder.encode(std::tuple{uint16_t{1}, committed, state, history_rows,
                                   snapshots, chain_id_});
}

bool engine::load_backup(std::string_view backup_path) {
  if (backup_path.empty()) {
    return false;
  }
  if (!std::filesystem::exists(backup_path)) {
    spdlog::info("No backup file found at '{}'", backup_path);
    return false;
  }

  auto input = std::ifstream{backup_path.data(), std::ios::binary};
  if (!input.good()) {
    spdlog::error("Failed opening backup file '{}'", backup_path);
    return false;
  }
  auto bytes = std::vector<uint8_t>{std::istreambuf_iterator<char>{input},
                                    std::istreambuf_iterator<char>{}};
  if (bytes.empty()) {
    spdlog::warn("Backup file '{}' is empty", backup_path);
    return false;
  }

  auto error = std::string{};
  auto imported = load_backup(
      charter::schema::bytes_view_t{bytes.data(), bytes.size()}, error);
  if (!imported) {
    spdlog::error("Failed importing backup '{}': {}", backup_path, error);
    return false;
  }
  spdlog::info("Imported backup from '{}'", backup_path);
  return true;
}

bool engine::load_backup(const charter::schema::bytes_view_t& backup,
                         std::string& error) {
  auto lock = std::scoped_lock{mutex_};
  auto encoder = encoder_t{};
  auto decoded = encoder.try_decode<
      std::tuple<uint16_t, std::optional<charter::storage::committed_state>,
                 std::vector<charter::storage::key_value_entry_t>,
                 std::vector<charter::storage::key_value_entry_t>,
                 std::vector<charter::storage::key_value_entry_t>,
                 charter::schema::hash32_t>>(backup);
  if (!decoded) {
    error = "failed to decode backup bundle";
    append_security_event(
        storage_, encoder,
        charter::schema::security_event_type_t::backup_import_failed,
        charter::schema::security_event_severity_t::error, 1, error,
        std::nullopt, std::nullopt, std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_));
    return false;
  }
  if (std::get<0>(decoded.value()) != 1) {
    error = "unsupported backup bundle version";
    append_security_event(
        storage_, encoder,
        charter::schema::security_event_type_t::backup_import_failed,
        charter::schema::security_event_severity_t::error, 1, error,
        std::nullopt, std::nullopt, std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_));
    return false;
  }
  if (std::get<5>(decoded.value()) != chain_id_) {
    error = "backup chain_id mismatch";
    append_security_event(
        storage_, encoder,
        charter::schema::security_event_type_t::backup_import_failed,
        charter::schema::security_event_severity_t::error, 1, error,
        std::nullopt, std::nullopt, std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_));
    return false;
  }

  auto state_prefix = charter::schema::make_bytes(kStatePrefix);
  auto history_prefix = charter::schema::make_bytes(kHistoryPrefix);
  auto snapshot_prefix = charter::schema::make_bytes(kSnapshotPrefix);

  storage_.replace_by_prefix(
      charter::schema::bytes_view_t{state_prefix.data(), state_prefix.size()},
      std::get<2>(decoded.value()));
  storage_.replace_by_prefix(
      charter::schema::bytes_view_t{history_prefix.data(),
                                    history_prefix.size()},
      std::get<3>(decoded.value()));
  storage_.replace_by_prefix(
      charter::schema::bytes_view_t{snapshot_prefix.data(),
                                    snapshot_prefix.size()},
      std::get<4>(decoded.value()));

  if (std::get<1>(decoded.value()).has_value()) {
    storage_.save_committed_state(std::get<1>(decoded.value()).value());
  }
  load_persisted_state();
  return true;
}

replay_result engine::replay_history() {
  auto lock = std::scoped_lock{mutex_};
  auto result = replay_result{};
  auto expected_committed = storage_.load_committed_state();

  auto history_prefix = charter::schema::make_bytes(kHistoryPrefix);
  auto history_rows = storage_.list_by_prefix(charter::schema::bytes_view_t{
      history_prefix.data(), history_prefix.size()});
  auto state_prefix = charter::schema::make_bytes(kStatePrefix);
  storage_.replace_by_prefix(
      charter::schema::bytes_view_t{state_prefix.data(), state_prefix.size()},
      {});

  auto encoder = encoder_t{};
  auto expected_nonces = std::map<std::string, uint64_t>{};
  auto rolling_hash = charter::schema::make_zero_hash();
  auto max_height = uint64_t{};
  for (const auto& [key, value] : history_rows) {
    auto parsed = parse_history_key(
        charter::schema::bytes_view_t{key.data(), key.size()});
    if (!parsed) {
      continue;
    }
    auto [height, index] = *parsed;
    current_block_time_ms_ = height * 1000;
    auto decoded =
        encoder.try_decode<std::tuple<uint32_t, charter::schema::bytes_t>>(
            charter::schema::bytes_view_t{value.data(), value.size()});
    if (!decoded) {
      result.error = "failed decoding history record";
      spdlog::warn("History replay failed: {}", result.error);
      return result;
    }
    auto stored_code = std::get<0>(decoded.value());
    auto raw_tx = std::get<1>(decoded.value());
    max_height = std::max(max_height, height);
    result.tx_count += 1;

    auto decode_error = std::string{};
    auto maybe_tx = decode_transaction(
        charter::schema::bytes_view_t{raw_tx.data(), raw_tx.size()},
        decode_error);
    if (!maybe_tx) {
      if (stored_code == 1) {
        continue;
      }
      result.error = "failed decoding history tx during replay";
      spdlog::warn("History replay failed: {}", result.error);
      return result;
    }
    auto signer_key = make_signer_cache_key(maybe_tx->signer);
    auto expected_nonce = std::optional<uint64_t>{};
    if (auto it = expected_nonces.find(signer_key);
        it != std::end(expected_nonces)) {
      expected_nonce = it->second;
    }
    auto validation = validate_tx(*maybe_tx, "charter.replay", expected_nonce);
    if (validation.code != stored_code) {
      result.error = "history tx validation code mismatch during replay";
      spdlog::warn("History replay failed: {}", result.error);
      return result;
    }
    if (stored_code != 0) {
      continue;
    }
    auto execution = execute_operation(*maybe_tx);
    if (execution.code != 0) {
      result.error = "history tx execution failed during replay";
      spdlog::warn("History replay failed: {}", result.error);
      return result;
    }
    auto nonce_key = make_nonce_key(maybe_tx->signer);
    storage_.put(
        encoder,
        charter::schema::bytes_view_t{nonce_key.data(), nonce_key.size()},
        maybe_tx->nonce);
    expected_nonces[signer_key] = maybe_tx->nonce + 1;
    rolling_hash = fold_app_hash(rolling_hash, raw_tx, height, index);
    result.applied_count += 1;
  }

  last_committed_height_ = static_cast<int64_t>(max_height);
  last_committed_state_root_ = rolling_hash;
  pending_state_root_ = rolling_hash;
  storage_.save_committed_state(charter::storage::committed_state{
      .height = last_committed_height_, .state_root = last_committed_state_root_});
  load_persisted_state();

  if (expected_committed.has_value() &&
      (expected_committed->height != last_committed_height_ ||
       expected_committed->state_root != last_committed_state_root_)) {
    spdlog::warn(
        "Replay checkpoint mismatch (stored height={}, replayed height={})",
        expected_committed->height, last_committed_height_);
    result.error = "replayed state differs from prior committed checkpoint";
    auto encoder = encoder_t{};
    append_security_event(
        storage_, encoder,
        charter::schema::security_event_type_t::replay_checkpoint_mismatch,
        charter::schema::security_event_severity_t::warning, 0, result.error,
        std::nullopt, std::nullopt, std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_));
  }
  result.ok = true;
  result.last_height = last_committed_height_;
  result.state_root = last_committed_state_root_;
  spdlog::info("History replay complete: txs={}, applied={}, height={}",
               result.tx_count, result.applied_count, result.last_height);
  return result;
}

void engine::set_signature_verifier(signature_verifier_t verifier) {
  auto lock = std::scoped_lock{mutex_};
  signature_verifier_ = std::move(verifier);
}

std::vector<snapshot_descriptor> engine::list_snapshots() const {
  auto lock = std::scoped_lock{mutex_};
  return snapshots_;
}

std::optional<charter::schema::bytes_t> engine::load_snapshot_chunk(
    uint64_t height,
    uint32_t format,
    uint32_t chunk) const {
  auto lock = std::scoped_lock{mutex_};
  auto loaded = storage_.load_snapshot_chunk(height, format, chunk);
  if (!loaded) {
    spdlog::warn("Snapshot chunk not found: h={}, f={}, c={}", height, format,
                 chunk);
  }
  return loaded;
}

offer_snapshot_result engine::offer_snapshot(
    const snapshot_descriptor& offered,
    const charter::schema::hash32_t& trusted_state_root) {
  auto lock = std::scoped_lock{mutex_};
  if (offered.format != 1) {
    spdlog::warn("Rejecting snapshot offer with unsupported format {}",
                 offered.format);
    auto encoder = encoder_t{};
    append_security_event(
        storage_, encoder,
        charter::schema::security_event_type_t::snapshot_rejected,
        charter::schema::security_event_severity_t::warning, 0,
        "snapshot format rejected", std::nullopt, std::nullopt, std::nullopt,
        current_block_time_ms_, static_cast<uint64_t>(last_committed_height_));
    return offer_snapshot_result::reject_format;
  }
  if (offered.chunks != 1) {
    spdlog::warn("Rejecting snapshot offer with unsupported chunk count {}",
                 offered.chunks);
    auto encoder = encoder_t{};
    append_security_event(
        storage_, encoder,
        charter::schema::security_event_type_t::snapshot_rejected,
        charter::schema::security_event_severity_t::warning, 0,
        "snapshot chunk count rejected", std::nullopt, std::nullopt,
        std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_));
    return offer_snapshot_result::reject;
  }
  if (!trusted_state_root.empty() && trusted_state_root != offered.hash) {
    spdlog::warn("Rejecting snapshot offer at height {} due to hash mismatch",
                 offered.height);
    auto encoder = encoder_t{};
    append_security_event(
        storage_, encoder,
        charter::schema::security_event_type_t::snapshot_rejected,
        charter::schema::security_event_severity_t::warning, 0,
        "snapshot trusted hash rejected", std::nullopt, std::nullopt,
        std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_));
    return offer_snapshot_result::reject;
  }
  pending_snapshot_offer_ = offered;
  return offer_snapshot_result::accept;
}

apply_snapshot_chunk_result engine::apply_snapshot_chunk(
    uint32_t index,
    const charter::schema::bytes_view_t& chunk,
    const std::string& sender) {
  if (sender.empty()) {
    spdlog::warn("Rejecting snapshot chunk from empty sender");
    return apply_snapshot_chunk_result::reject_snapshot;
  }
  auto lock = std::scoped_lock{mutex_};
  if (index != 0 || chunk.empty() || !pending_snapshot_offer_.has_value()) {
    return apply_snapshot_chunk_result::retry_snapshot;
  }
  auto computed_hash = charter::blake3::hash(
      charter::schema::bytes_view_t{chunk.data(), chunk.size()});
  if (computed_hash != pending_snapshot_offer_->hash) {
    spdlog::warn("Snapshot chunk hash mismatch for offered height {}",
                 pending_snapshot_offer_->height);
    auto encoder = encoder_t{};
    append_security_event(
        storage_, encoder,
        charter::schema::security_event_type_t::snapshot_rejected,
        charter::schema::security_event_severity_t::warning, 0,
        "snapshot chunk hash mismatch", std::nullopt, std::nullopt,
        std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_));
    return apply_snapshot_chunk_result::reject_snapshot;
  }
  auto restore_error = std::string{};
  if (!restore_state_snapshot_chunk(storage_, chunk, restore_error)) {
    spdlog::error("Failed to restore snapshot chunk: {}", restore_error);
    auto encoder = encoder_t{};
    append_security_event(
        storage_, encoder,
        charter::schema::security_event_type_t::snapshot_rejected,
        charter::schema::security_event_severity_t::error, 0, restore_error,
        std::nullopt, std::nullopt, std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_));
    return apply_snapshot_chunk_result::reject_snapshot;
  }

  last_committed_height_ =
      static_cast<int64_t>(pending_snapshot_offer_->height);
  last_committed_state_root_ = pending_snapshot_offer_->hash;
  pending_state_root_ = last_committed_state_root_;
  storage_.save_committed_state(charter::storage::committed_state{
      .height = last_committed_height_, .state_root = last_committed_state_root_});
  auto existing =
      std::find_if(std::begin(snapshots_), std::end(snapshots_),
                   [&](const snapshot_descriptor& value) {
                     return value.height == pending_snapshot_offer_->height &&
                            value.format == pending_snapshot_offer_->format;
                   });
  if (existing == std::end(snapshots_)) {
    snapshots_.push_back(*pending_snapshot_offer_);
  } else {
    *existing = *pending_snapshot_offer_;
  }
  pending_snapshot_offer_.reset();
  spdlog::info("Applied snapshot chunk {}", index);
  auto encoder = encoder_t{};
  append_security_event(
      storage_, encoder,
      charter::schema::security_event_type_t::snapshot_applied,
      charter::schema::security_event_severity_t::info, 0, "snapshot applied",
      std::nullopt, std::nullopt, std::nullopt, current_block_time_ms_,
      static_cast<uint64_t>(last_committed_height_));
  return apply_snapshot_chunk_result::accept;
}

void engine::create_snapshot_if_due(int64_t height) {
  if (snapshot_interval_ == 0 || height <= 0 ||
      (height % static_cast<int64_t>(snapshot_interval_)) != 0) {
    return;
  }

  auto chunk = make_state_snapshot_chunk(storage_);
  auto snapshot =
      make_snapshot_descriptor(static_cast<uint64_t>(height), chunk);
  storage_.save_snapshot(
      charter::storage::snapshot_descriptor{.height = snapshot.height,
                                            .format = snapshot.format,
                                            .chunks = snapshot.chunks,
                                            .hash = snapshot.hash,
                                            .metadata = snapshot.metadata},
      chunk);

  auto existing = std::find_if(std::begin(snapshots_), std::end(snapshots_),
                               [&](const snapshot_descriptor& value) {
                                 return value.height == snapshot.height &&
                                        value.format == snapshot.format;
                               });
  if (existing == std::end(snapshots_)) {
    snapshots_.push_back(snapshot);
  } else {
    *existing = snapshot;
  }
  spdlog::info("Created snapshot at height {} format {}", snapshot.height,
               snapshot.format);
}

void engine::load_persisted_state() {
  spdlog::debug("Loading persisted engine state");
  if (auto committed = storage_.load_committed_state()) {
    last_committed_height_ = committed->height;
    last_committed_state_root_ = committed->state_root;
    pending_state_root_ = committed->state_root;
  }

  auto stored_snapshots = storage_.list_snapshots();
  snapshots_.clear();
  snapshots_.reserve(stored_snapshots.size());
  for (const auto& snapshot : stored_snapshots) {
    snapshots_.push_back(snapshot_descriptor{.height = snapshot.height,
                                             .format = snapshot.format,
                                             .chunks = snapshot.chunks,
                                             .hash = snapshot.hash,
                                             .metadata = snapshot.metadata});
  }
}

}  // namespace charter::execution

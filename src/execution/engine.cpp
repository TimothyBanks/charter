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
#include <charter/schema/asset_state.hpp>
#include <charter/schema/attestation_record.hpp>
#include <charter/schema/destination_update_state.hpp>
#include <charter/schema/disable_asset.hpp>
#include <charter/schema/encoding/scale/encoder.hpp>
#include <charter/schema/encoding/scale/transaction.hpp>
#include <charter/schema/intent_state.hpp>
#include <charter/schema/key/engine_keys.hpp>
#include <charter/schema/propose_destination_update.hpp>
#include <charter/schema/query_error_code.hpp>
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
using namespace charter::schema::key;

namespace {

inline constexpr auto kQueryCodespace = std::string_view{"charter.query"};
inline constexpr auto kExecuteCodespace = std::string_view{"charter.execute"};
inline constexpr auto kCheckTxCodespace = std::string_view{"charter.checktx"};
inline constexpr auto kProposalCodespace = std::string_view{"charter.proposal"};

using rocksdb_storage_t =
    charter::storage::storage<charter::storage::rocksdb_storage_tag>;
using scale_encoder_t = charter::schema::encoding::encoder<
    charter::schema::encoding::scale_encoder_tag>;

charter::schema::hash32_t make_chain_id() {
  return charter::blake3::hash(std::string_view{"charter-poc-chain"});
}

std::string payload_type_name(
    const charter::schema::transaction_payload_t& payload) {
  return std::visit(
      overloaded{[](const charter::schema::activate_policy_set_t&) {
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
                 [](const charter::schema::disable_asset_t&) {
                   return std::string{"disable_asset"};
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
                 [](const charter::schema::upsert_asset_t&) {
                   return std::string{"upsert_asset"};
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

template <typename Encoder>
void append_transaction_result_event(
    Encoder encoder,
    charter::schema::transaction_result_t& result,
    uint64_t height,
    uint32_t index,
    const std::optional<charter::schema::transaction_t>& maybe_tx) {
  auto event = charter::schema::transaction_event_t{};
  event.type = "charter.tx_result";

  auto codespace = result.codespace.empty() ? std::string{kExecuteCodespace}
                                            : result.codespace;

  event.attributes.emplace_back(charter::schema::transaction_event_attribute_t{
      .key = "code", .value = std::to_string(result.code), .index = true});
  event.attributes.emplace_back(charter::schema::transaction_event_attribute_t{
      .key = "success",
      .value = result.code == 0 ? "true" : "false",
      .index = true});
  event.attributes.emplace_back(charter::schema::transaction_event_attribute_t{
      .key = "codespace", .value = codespace, .index = true});
  event.attributes.emplace_back(charter::schema::transaction_event_attribute_t{
      .key = "height", .value = std::to_string(height), .index = true});
  event.attributes.emplace_back(charter::schema::transaction_event_attribute_t{
      .key = "tx_index", .value = std::to_string(index), .index = true});

  if (!result.log.empty()) {
    event.attributes.emplace_back(
        charter::schema::transaction_event_attribute_t{
            .key = "log", .value = result.log, .index = false});
  }

  if (!result.info.empty()) {
    event.attributes.emplace_back(
        charter::schema::transaction_event_attribute_t{
            .key = "info", .value = result.info, .index = false});
  }

  if (maybe_tx.has_value()) {
    auto encoded_signer = encoder.encode(maybe_tx->signer);
    event.attributes.emplace_back(
        charter::schema::transaction_event_attribute_t{
            .key = "signer",
            .value = to_hex(charter::schema::bytes_view_t{
                encoded_signer.data(), encoded_signer.size()}),
            .index = true});
    event.attributes.emplace_back(
        charter::schema::transaction_event_attribute_t{
            .key = "nonce",
            .value = std::to_string(maybe_tx->nonce),
            .index = true});
    event.attributes.emplace_back(
        charter::schema::transaction_event_attribute_t{
            .key = "payload_type",
            .value = payload_type_name(maybe_tx->payload),
            .index = true});
  } else {
    event.attributes.emplace_back(
        charter::schema::transaction_event_attribute_t{
            .key = "payload_type", .value = "decode_failed", .index = true});
  }

  result.events.emplace_back(std::move(event));
}

template <typename Encoder>
bool signer_ids_equal(Encoder& encoder,
                      const charter::schema::signer_id_t& lhs,
                      const charter::schema::signer_id_t& rhs) {
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
          [&](const charter::schema::upsert_asset_t&)
              -> std::optional<charter::schema::policy_scope_t> {
            return std::nullopt;
          },
          [&](const charter::schema::disable_asset_t&)
              -> std::optional<charter::schema::policy_scope_t> {
            return std::nullopt;
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
  // Baseline authorization matrix. Role assignments can later be satisfied by
  // either scoped overrides or active policy-set role maps.
  using role_t = charter::schema::role_id_t;
  return std::visit(
      overloaded{[&](const charter::schema::create_workspace_t&) {
                   return std::vector<role_t>{};
                 },
                 [&](const charter::schema::create_vault_t&) {
                   return std::vector<role_t>{role_t::admin};
                 },
                 [&](const charter::schema::upsert_asset_t&) {
                   return std::vector<role_t>{role_t::admin};
                 },
                 [&](const charter::schema::disable_asset_t&) {
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

template <typename Encoder>
bool workspace_exists(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::hash32_t& workspace_id) {
  auto key = make_workspace_key(encoder, workspace_id);
  auto workspace = storage.get<charter::schema::workspace_state_t>(
      encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  return workspace.has_value();
}

template <typename Encoder>
std::optional<charter::schema::workspace_state_t> load_workspace_state(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::hash32_t& workspace_id) {
  auto key = make_workspace_key(encoder, workspace_id);
  return storage.get<charter::schema::workspace_state_t>(
      encoder, charter::schema::bytes_view_t{key.data(), key.size()});
}

template <typename Encoder>
bool vault_exists(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id) {
  auto key = make_vault_key(encoder, workspace_id, vault_id);
  auto vault = storage.get<charter::schema::vault_state_t>(
      encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  return vault.has_value();
}

template <typename Encoder>
std::optional<charter::schema::asset_state_t> load_asset_state(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::hash32_t& asset_id) {
  auto key = make_asset_key(encoder, asset_id);
  return storage.get<charter::schema::asset_state_t>(
      encoder, charter::schema::bytes_view_t{key.data(), key.size()});
}

template <typename Encoder>
bool destination_enabled(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& destination_id) {
  auto key = make_destination_key(encoder, workspace_id, destination_id);
  auto destination = storage.get<charter::schema::destination_state_t>(
      encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  return destination.has_value() && destination->enabled;
}

template <typename Encoder>
std::optional<charter::schema::degraded_mode_state_t> load_degraded_mode_state(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder) {
  auto key = make_degraded_mode_key(encoder);
  return storage.get<charter::schema::degraded_mode_state_t>(
      encoder, charter::schema::bytes_view_t{key.data(), key.size()});
}

template <typename Encoder>
charter::schema::degraded_mode_t current_degraded_mode(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder) {
  auto state = load_degraded_mode_state(storage, encoder);
  if (!state.has_value()) {
    return charter::schema::degraded_mode_t::normal;
  }
  return state->mode;
}

template <typename Encoder>
bool signer_quarantined(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::signer_id_t& signer,
    const uint64_t now_ms) {
  auto key = make_signer_quarantine_key(encoder, signer);
  auto state = storage.get<charter::schema::signer_quarantine_state_t>(
      encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  if (!state.has_value() || !state->quarantined) {
    return false;
  }
  if (!state->until.has_value()) {
    return true;
  }
  return now_ms <= state->until.value();
}

template <typename Encoder>
void append_security_event(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::security_event_type_t type,
    const charter::schema::security_event_severity_t severity,
    const uint32_t code,
    const std::string_view message,
    const std::optional<charter::schema::signer_id_t>& signer,
    const std::optional<charter::schema::hash32_t>& workspace_id,
    const std::optional<charter::schema::hash32_t>& vault_id,
    const uint64_t now_ms,
    const uint64_t block_height,
    uint64_t* security_event_total = nullptr,
    std::map<uint32_t, uint64_t>* security_severity_counts = nullptr) {
  auto seq_key = make_event_sequence_key(encoder);
  auto next_id =
      storage
          .get<uint64_t>(encoder, charter::schema::bytes_view_t{seq_key.data(),
                                                                seq_key.size()})
          .value_or(1);
  auto event_key = make_event_key(encoder, next_id);
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
  if (security_event_total != nullptr && security_severity_counts != nullptr) {
    *security_event_total += 1;
    (*security_severity_counts)[static_cast<uint32_t>(severity)] += 1;
  }
}

template <typename Encoder>
bool policy_scope_exists(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
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

template <typename Encoder>
bool active_policy_exists(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::policy_scope_t& scope) {
  auto key = make_active_policy_key(encoder, scope);
  auto pointer = storage.get<charter::schema::active_policy_pointer_t>(
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
  // Effective policy values after merging all matching rules for an operation.
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

template <typename Encoder>
std::optional<policy_requirements> resolve_policy_requirements(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::policy_scope_t& scope,
    const charter::schema::operation_type_t operation_type) {
  auto active_key = make_active_policy_key(encoder, scope);
  auto pointer = storage.get<charter::schema::active_policy_pointer_t>(
      encoder,
      charter::schema::bytes_view_t{active_key.data(), active_key.size()});
  if (!pointer) {
    return std::nullopt;
  }

  auto policy_key = make_policy_set_key(encoder, pointer->policy_set_id,
                                        pointer->policy_set_version);
  auto policy = storage.get<charter::schema::policy_set_state_t>(
      encoder,
      charter::schema::bytes_view_t{policy_key.data(), policy_key.size()});
  if (!policy) {
    return std::nullopt;
  }

  auto requirements = policy_requirements{};
  requirements.policy_set_id = pointer->policy_set_id;
  requirements.policy_version = pointer->policy_set_version;

  // Merge strategy for matching rules:
  // - threshold: max (most restrictive approval count)
  // - delay_ms: max (longest timelock)
  // - per_transaction_limit: min (smallest spend cap)
  // - destination/SoD booleans: logical OR (any rule can require)
  // - claim requirements: set union by claim id
  // - velocity limits: append all windows/caps
  for (const auto& rule : policy->rules) {
    if (rule.operation != operation_type) {
      continue;
    }

    for (const auto& approval : rule.approvals) {
      // Higher threshold tightens approval requirements.
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
          // Longest delay wins to preserve the strictest timelock.
          requirements.delay_ms =
              std::max(requirements.delay_ms, time_lock.delay);
        }
      }
    }

    for (const auto& limit : rule.limits) {
      // Smallest allowed amount wins (tightest per-transaction cap).
      if (!requirements.per_transaction_limit.has_value() ||
          limit.per_transaction_amount <
              requirements.per_transaction_limit.value()) {
        requirements.per_transaction_limit = limit.per_transaction_amount;
      }
    }

    for (const auto& destination_rule : rule.destination_rules) {
      // Any matching rule can require whitelist enforcement.
      requirements.require_whitelisted_destination =
          requirements.require_whitelisted_destination ||
          destination_rule.require_whitelisted;
    }

    for (const auto& claim : rule.required_claims) {
      // Deduplicate claim requirements by claim id.
      auto existing = std::ranges::find_if(
          requirements.claim_requirements,
          [&](const charter::schema::claim_requirement_t& requirement) {
            return requirement.claim == claim;
          });

      if (existing == std::end(requirements.claim_requirements)) {
        requirements.claim_requirements.emplace_back(
            charter::schema::claim_requirement_t{
                .claim = claim,
                .minimum_valid_until = std::nullopt,
                .trusted_issuers = std::nullopt});
      }
    }

    for (const auto& velocity_limit : rule.velocity_limits) {
      // Preserve all configured velocity caps for later enforcement.
      requirements.velocity_limits.emplace_back(velocity_limit);
    }
  }

  return requirements;
}

template <typename Encoder>
std::optional<charter::schema::policy_set_state_t> load_policy_set(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::hash32_t& policy_set_id,
    const uint32_t policy_version) {
  auto key = make_policy_set_key(encoder, policy_set_id, policy_version);
  return storage.get<charter::schema::policy_set_state_t>(
      encoder, charter::schema::bytes_view_t{key.data(), key.size()});
}

template <typename Encoder>
std::optional<charter::schema::policy_set_state_t>
load_active_policy_set_for_scope(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::policy_scope_t& scope) {
  auto active_key = make_active_policy_key(encoder, scope);
  auto pointer = storage.get<charter::schema::active_policy_pointer_t>(
      encoder,
      charter::schema::bytes_view_t{active_key.data(), active_key.size()});
  if (!pointer) {
    return std::nullopt;
  }
  return load_policy_set(storage, encoder, pointer->policy_set_id,
                         pointer->policy_set_version);
}

template <typename Encoder>
bool role_granted_by_policy(Encoder& encoder,
                            const charter::schema::policy_set_state_t& policy,
                            const charter::schema::role_id_t role,
                            const charter::schema::signer_id_t& signer) {
  auto role_it = std::ranges::find_if(
      policy.roles,
      [&](const std::pair<charter::schema::role_id_t,
                          std::vector<charter::schema::signer_id_t>>& entry) {
        return entry.first == role;
      });
  if (role_it == std::end(policy.roles)) {
    return false;
  }
  return std::ranges::any_of(
      role_it->second, [&](const charter::schema::signer_id_t& candidate) {
        return signer_ids_equal(encoder, candidate, signer);
      });
}

template <typename Encoder>
bool role_granted_by_override(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::policy_scope_t& scope,
    const charter::schema::signer_id_t& signer,
    const charter::schema::role_id_t role,
    const uint64_t now_ms,
    std::optional<bool>& has_override) {
  // Scoped role assignment overrides policy role maps.
  // If an override exists and is disabled, we treat that as explicit deny.
  auto key = make_role_assignment_key(encoder, scope, signer, role);
  auto assignment = storage.get<charter::schema::role_assignment_state_t>(
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

template <typename Encoder>
bool scope_has_role(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::policy_scope_t& scope,
    const charter::schema::signer_id_t& signer,
    const charter::schema::role_id_t role,
    const uint64_t now_ms) {
  // Precedence:
  // 1) explicit scoped override
  // 2) active policy-set role membership
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
  return role_granted_by_policy(encoder, policy.value(), role, signer);
}

template <typename Encoder>
bool signer_has_role_for_scope(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
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
    // Vault-scoped operations can inherit workspace-level role grants.
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

template <typename Encoder>
bool signer_has_required_global_role(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::signer_id_t& signer,
    const std::vector<charter::schema::role_id_t>& required_roles,
    const uint64_t now_ms) {
  // Global fallback role scan used for operations without an explicit scope.
  auto prefix = make_prefix_key(encoder, kRoleAssignmentKeyPrefix);
  auto rows = storage.list_by_prefix(
      charter::schema::bytes_view_t{prefix.data(), prefix.size()});
  for (const auto& [unused_key, value] : rows) {
    (void)unused_key;
    auto assignment =
        encoder.template try_decode<charter::schema::role_assignment_state_t>(
            charter::schema::bytes_view_t{value.data(), value.size()});
    if (!assignment.has_value()) {
      continue;
    }
    if (!signer_ids_equal(encoder, assignment->subject, signer)) {
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
    if (std::ranges::find(required_roles, assignment->role) !=
        std::end(required_roles)) {
      return true;
    }
  }
  return false;
}

template <typename Encoder>
bool signer_authorized_for_payload(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::transaction_payload_t& payload,
    const charter::schema::signer_id_t& signer,
    const uint64_t now_ms) {
  // Most operations authorize within a scope (workspace or vault). Operations
  // without scope fallback to any active global role assignment.
  auto required_roles = required_roles_for_payload(payload);
  if (required_roles.empty()) {
    return true;
  }

  auto scope = scope_from_payload(payload);
  if (!scope.has_value()) {
    return signer_has_required_global_role(storage, encoder, signer,
                                           required_roles, now_ms);
  }

  return std::ranges::any_of(required_roles, [&](const auto role) {
    return signer_has_role_for_scope(storage, encoder, scope.value(), signer,
                                     role, now_ms);
  });
}

bool is_policy_denial_code(const uint32_t code) {
  using charter::schema::transaction_error_code;
  switch (code) {
    case static_cast<uint32_t>(
        transaction_error_code::policy_resolution_failed):
    case static_cast<uint32_t>(transaction_error_code::intent_expired):
    case static_cast<uint32_t>(transaction_error_code::intent_not_executable):
    case static_cast<uint32_t>(transaction_error_code::limit_exceeded):
    case static_cast<uint32_t>(
        transaction_error_code::destination_not_whitelisted):
    case static_cast<uint32_t>(
        transaction_error_code::claim_requirement_unsatisfied):
    case static_cast<uint32_t>(transaction_error_code::velocity_limit_exceeded):
    case static_cast<uint32_t>(
        transaction_error_code::separation_of_duties_violated):
    case static_cast<uint32_t>(
        transaction_error_code::destination_update_not_executable):
      return true;
    default:
      return false;
  }
}

charter::schema::security_event_type_t event_type_for_transaction_error(
    const uint32_t code,
    const bool validation_phase) {
  if (code ==
      static_cast<uint32_t>(
          charter::schema::transaction_error_code::authorization_denied)) {
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

charter::schema::transaction_result_t make_error_transaction_result(
    uint32_t code,
    std::string log,
    std::string info,
    std::string codespace);
charter::schema::transaction_result_t make_error_transaction_result(
    charter::schema::transaction_error_code code,
    std::string log,
    std::string info,
    std::string codespace);

template <typename Encoder>
bool enforce_velocity_limits(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id,
    const charter::schema::intent_action_t& action,
    const std::vector<charter::schema::velocity_limit_rule_t>& limits,
    const uint64_t now_ms,
    charter::schema::transaction_result_t& result,
    const std::string_view codespace) {
  // Velocity checks are pre-execution guards. They evaluate aggregate spend in
  // a deterministic time bucket without mutating counters.
  auto transfer = transfer_asset_and_amount(action);
  if (!transfer.has_value()) {
    return true;
  }
  const auto& [asset_id, amount] = transfer.value();
  for (const auto& limit : limits) {
    if (limit.asset_id.has_value() && limit.asset_id.value() != asset_id) {
      continue;
    }
    // Each rule is evaluated against its own deterministic window bucket.
    auto window_start = velocity_window_start_ms(now_ms, limit.window);
    auto key =
        make_velocity_counter_key(encoder, workspace_id, vault_id,
                                  limit.asset_id, limit.window, window_start);
    auto counter = storage.get<charter::schema::velocity_counter_state_t>(
        encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    auto used = counter.has_value() ? counter->used_amount
                                    : charter::schema::amount_t{0};
    if (used + charter::schema::amount_t{amount} > limit.maximum_amount) {
      result = make_error_transaction_result(
          charter::schema::transaction_error_code::velocity_limit_exceeded,
          "velocity limit exceeded",
          "cumulative velocity window amount exceeded policy maximum",
          std::string{codespace});
      return false;
    }
  }
  return true;
}

template <typename Encoder>
void apply_velocity_limits(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& vault_id,
    const charter::schema::intent_action_t& action,
    const std::vector<charter::schema::velocity_limit_rule_t>& limits,
    const uint64_t now_ms) {
  // Velocity counters are updated only after an operation succeeds so failed
  // proposals never consume policy budget.
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
    auto key =
        make_velocity_counter_key(encoder, workspace_id, vault_id,
                                  limit.asset_id, limit.window, window_start);
    auto counter = storage.get<charter::schema::velocity_counter_state_t>(
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

template <typename Encoder>
bool attestation_satisfies_requirement(
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    Encoder& encoder,
    const charter::schema::hash32_t& workspace_id,
    const charter::schema::hash32_t& subject,
    const charter::schema::claim_requirement_t& requirement,
    uint64_t now_ms) {
  // Requirement check supports:
  // - explicit trusted issuer set (point lookups)
  // - any issuer (prefix scan)
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
    // Fast path: issuer-constrained attestation checks.
    for (const auto& issuer : *requirement.trusted_issuers) {
      auto key = make_attestation_key(encoder, workspace_id, subject,
                                      requirement.claim, issuer);
      auto record = storage.get<charter::schema::attestation_record_t>(
          encoder, charter::schema::bytes_view_t{key.data(), key.size()});
      if (record.has_value() && matches_record(record.value())) {
        return true;
      }
    }
    return false;
  }

  auto prefix = make_attestation_prefix_key(encoder, workspace_id, subject,
                                            requirement.claim);
  // Broad path: any active record for claim is acceptable.
  auto rows = storage.list_by_prefix(
      charter::schema::bytes_view_t{prefix.data(), prefix.size()});
  for (const auto& [unused_key, value] : rows) {
    (void)unused_key;
    auto record =
        encoder.template try_decode<charter::schema::attestation_record_t>(
            charter::schema::bytes_view_t{value.data(), value.size()});
    if (record.has_value() && matches_record(record.value())) {
      return true;
    }
  }
  return false;
}

charter::schema::transaction_result_t make_error_transaction_result(
    uint32_t code,
    std::string log,
    std::string info,
    std::string codespace) {
  spdlog::error("tx error: code={} codespace='{}' log='{}' info='{}'", code,
                codespace, log, info);
  auto result = charter::schema::transaction_result_t{};
  result.code = code;
  result.log = std::move(log);
  result.info = std::move(info);
  result.codespace = std::move(codespace);
  return result;
}

charter::schema::transaction_result_t make_error_transaction_result(
    charter::schema::transaction_error_code code,
    std::string log,
    std::string info,
    std::string codespace) {
  return make_error_transaction_result(static_cast<uint32_t>(code),
                                       std::move(log), std::move(info),
                                       std::move(codespace));
}

charter::schema::query_result_t make_error_query_result(
    uint32_t code,
    std::string log,
    std::string info,
    std::string codespace,
    int64_t height,
    const charter::schema::bytes_view_t& key) {
  spdlog::error("query error: code={} codespace='{}' log='{}' info='{}'", code,
                codespace, log, info);
  auto result = charter::schema::query_result_t{};
  result.code = code;
  result.log = std::move(log);
  result.info = std::move(info);
  result.key = charter::schema::make_bytes(key);
  result.codespace = std::move(codespace);
  result.height = height;
  return result;
}

charter::schema::query_result_t make_error_query_result(
    charter::schema::query_error_code code,
    std::string log,
    std::string info,
    std::string codespace,
    int64_t height,
    const charter::schema::bytes_view_t& key) {
  return make_error_query_result(static_cast<uint32_t>(code), std::move(log),
                                 std::move(info), std::move(codespace), height,
                                 key);
}

template <typename Encoder>
std::vector<charter::schema::bytes_t> make_state_prefixes(Encoder& encoder);

std::vector<charter::storage::key_value_entry_t> list_state_entries(
    const rocksdb_storage_t& storage,
    const std::vector<charter::schema::bytes_t>& state_prefixes);

template <typename Encoder>
std::optional<charter::schema::transaction_t> decode_transaction(
    Encoder& encoder,
    const charter::schema::bytes_view_t& raw_tx,
    std::string& decode_error);

struct query_request_context final {
  rocksdb_storage_t& storage;
  scale_encoder_t& encoder;
  int64_t last_committed_height;
  const charter::schema::hash32_t& last_committed_state_root;
  const charter::schema::hash32_t& chain_id;
  const uint64_t& metrics_transaction_total;
  const uint64_t& metrics_transaction_failed;
  const uint64_t& metrics_security_event_total;
  const uint64_t& metrics_snapshots_total;
  const std::map<uint32_t, uint64_t>& metrics_transaction_code_counts;
  const std::map<uint32_t, uint64_t>& metrics_security_severity_counts;
  const std::map<uint32_t, uint64_t>& metrics_intent_status_counts;
  charter::schema::bytes_view_t data;
};

template <typename RowFn>
void for_each_history_row(const rocksdb_storage_t& storage,
                          scale_encoder_t& encoder,
                          RowFn&& row_fn) {
  auto history_prefix = make_prefix_key(encoder, kHistoryPrefix);
  auto history_rows = storage.list_by_prefix(charter::schema::bytes_view_t{
      history_prefix.data(), history_prefix.size()});
  for (const auto& [key, value] : history_rows) {
    auto parsed = parse_history_key(
        encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    if (!parsed.has_value()) {
      continue;
    }
    auto decoded_row =
        encoder.try_decode<std::tuple<uint32_t, charter::schema::bytes_t>>(
            charter::schema::bytes_view_t{value.data(), value.size()});
    if (!decoded_row.has_value()) {
      continue;
    }
    row_fn(parsed->first, parsed->second, std::get<0>(*decoded_row),
           std::get<1>(*decoded_row));
  }
}

std::string hash_to_hex_string(const charter::schema::hash32_t& hash) {
  auto bytes = charter::schema::bytes_t{std::begin(hash), std::end(hash)};
  return to_hex(charter::schema::bytes_view_t{bytes.data(), bytes.size()});
}

struct decoded_transaction_summary final {
  std::string payload_name{"decode_failed"};
  uint64_t nonce{};
  std::string signer_hex{};
};

decoded_transaction_summary summarize_transaction_bytes(
    scale_encoder_t& encoder,
    const charter::schema::bytes_t& tx_bytes) {
  auto summary = decoded_transaction_summary{};
  auto decode_error = std::string{};
  auto maybe_tx = decode_transaction(
      encoder, charter::schema::bytes_view_t{tx_bytes.data(), tx_bytes.size()},
      decode_error);
  if (!maybe_tx.has_value()) {
    return summary;
  }

  summary.payload_name = payload_type_name(maybe_tx->payload);
  summary.nonce = maybe_tx->nonce;
  auto encoded_signer = encoder.encode(maybe_tx->signer);
  summary.signer_hex = to_hex(charter::schema::bytes_view_t{
      encoded_signer.data(), encoded_signer.size()});
  return summary;
}

struct explorer_transaction_summary final {
  std::string transaction_hash_hex{};
  decoded_transaction_summary transaction{};
};

explorer_transaction_summary make_explorer_transaction_summary(
    scale_encoder_t& encoder,
    const charter::schema::bytes_t& tx_bytes) {
  auto tx_hash = charter::blake3::hash(
      charter::schema::bytes_view_t{tx_bytes.data(), tx_bytes.size()});
  return explorer_transaction_summary{
      .transaction_hash_hex = hash_to_hex_string(tx_hash),
      .transaction = summarize_transaction_bytes(encoder, tx_bytes)};
}

struct engine_observability_snapshot final {
  uint64_t transaction_total{};
  uint64_t transaction_failed{};
  uint64_t security_event_total{};
  uint64_t snapshots_total{};
  std::map<uint32_t, uint64_t> transaction_code_counts;
  std::map<uint32_t, uint64_t> security_severity_counts;
  std::map<uint32_t, uint64_t> intent_status_counts;
};

void increment_counter(std::map<uint32_t, uint64_t>& counters,
                       const uint32_t key) {
  counters[key] += 1;
}

void decrement_counter_if_present(std::map<uint32_t, uint64_t>& counters,
                                  const uint32_t key) {
  auto existing = counters.find(key);
  if (existing == std::end(counters) || existing->second == 0) {
    return;
  }
  existing->second -= 1;
  if (existing->second == 0) {
    counters.erase(existing);
  }
}

void record_history_code_counters(
    uint32_t code,
    uint64_t& transaction_total,
    uint64_t& transaction_failed,
    std::map<uint32_t, uint64_t>& transaction_code_counts) {
  transaction_total += 1;
  increment_counter(transaction_code_counts, code);
  if (code != 0) {
    transaction_failed += 1;
  }
}

void record_security_event_counters(
    const charter::schema::security_event_severity_t severity,
    uint64_t& security_event_total,
    std::map<uint32_t, uint64_t>& security_severity_counts) {
  security_event_total += 1;
  increment_counter(security_severity_counts, static_cast<uint32_t>(severity));
}

void update_intent_status_counters(
    const std::optional<charter::schema::intent_status_t>& previous_status,
    const charter::schema::intent_status_t next_status,
    std::map<uint32_t, uint64_t>& intent_status_counts) {
  if (previous_status.has_value()) {
    decrement_counter_if_present(intent_status_counts,
                                 static_cast<uint32_t>(*previous_status));
  }
  increment_counter(intent_status_counts, static_cast<uint32_t>(next_status));
}

template <typename Encoder>
void put_intent_state_with_counters(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::bytes_t& intent_key,
    const std::optional<charter::schema::intent_status_t>& previous_status,
    const charter::schema::intent_state_t& next_state,
    std::map<uint32_t, uint64_t>& intent_status_counts) {
  update_intent_status_counters(previous_status, next_state.status,
                                intent_status_counts);
  storage.put(
      encoder,
      charter::schema::bytes_view_t{intent_key.data(), intent_key.size()},
      next_state);
}

void rebuild_observability_counters(
    const rocksdb_storage_t& storage,
    scale_encoder_t& encoder,
    const std::vector<charter::schema::snapshot_descriptor_t>& snapshots,
    uint64_t& transaction_total,
    uint64_t& transaction_failed,
    std::map<uint32_t, uint64_t>& transaction_code_counts,
    uint64_t& security_event_total,
    std::map<uint32_t, uint64_t>& security_severity_counts,
    std::map<uint32_t, uint64_t>& intent_status_counts,
    uint64_t& snapshots_total) {
  transaction_total = 0;
  transaction_failed = 0;
  security_event_total = 0;
  snapshots_total = static_cast<uint64_t>(snapshots.size());
  transaction_code_counts.clear();
  security_severity_counts.clear();
  intent_status_counts.clear();

  for_each_history_row(
      storage, encoder,
      [&](uint64_t /*height*/, uint32_t /*index*/, uint32_t code,
          const charter::schema::bytes_t& /*tx*/) {
        record_history_code_counters(code, transaction_total,
                                     transaction_failed,
                                     transaction_code_counts);
      });

  auto event_prefix = make_prefix_key(encoder, kEventPrefix);
  auto event_rows = storage.list_by_prefix(
      charter::schema::bytes_view_t{event_prefix.data(), event_prefix.size()});
  for (const auto& [unused_key, value] : event_rows) {
    (void)unused_key;
    auto event = encoder.try_decode<charter::schema::security_event_record_t>(
        charter::schema::bytes_view_t{value.data(), value.size()});
    if (!event.has_value()) {
      continue;
    }
    record_security_event_counters(event->severity, security_event_total,
                                   security_severity_counts);
  }

  auto intent_prefix = make_prefix_key(encoder, kIntentKeyPrefix);
  auto intent_rows = storage.list_by_prefix(charter::schema::bytes_view_t{
      intent_prefix.data(), intent_prefix.size()});
  for (const auto& [unused_key, value] : intent_rows) {
    (void)unused_key;
    auto intent = encoder.try_decode<charter::schema::intent_state_t>(
        charter::schema::bytes_view_t{value.data(), value.size()});
    if (!intent.has_value()) {
      continue;
    }
    increment_counter(intent_status_counts,
                      static_cast<uint32_t>(intent->status));
  }
}

engine_observability_snapshot collect_engine_observability(
    const query_request_context& request) {
  return engine_observability_snapshot{
      .transaction_total = request.metrics_transaction_total,
      .transaction_failed = request.metrics_transaction_failed,
      .security_event_total = request.metrics_security_event_total,
      .snapshots_total = request.metrics_snapshots_total,
      .transaction_code_counts = request.metrics_transaction_code_counts,
      .security_severity_counts = request.metrics_security_severity_counts,
      .intent_status_counts = request.metrics_intent_status_counts,
  };
}

charter::schema::query_result_t make_query_success_result(
    const query_request_context& request,
    charter::schema::bytes_t value) {
  auto result = charter::schema::query_result_t{};
  result.height = request.last_committed_height;
  result.codespace = std::string{kQueryCodespace};
  result.key = charter::schema::make_bytes(request.data);
  result.value = std::move(value);
  return result;
}

charter::schema::query_result_t make_query_error_result(
    const query_request_context& request,
    charter::schema::query_error_code code,
    std::string log,
    std::string info) {
  return make_error_query_result(code, std::move(log), std::move(info),
                                 std::string{kQueryCodespace},
                                 request.last_committed_height, request.data);
}

std::optional<charter::schema::query_result_t> require_empty_query_key(
    const query_request_context& request,
    std::string_view query_name) {
  if (request.data.empty()) {
    return std::nullopt;
  }

  return make_query_error_result(
      request, charter::schema::query_error_code::invalid_key, "invalid key",
      std::string{query_name} + " query does not accept key payload");
}

std::vector<std::tuple<uint8_t, uint64_t>> encode_intent_status_counts(
    const std::map<uint32_t, uint64_t>& intent_status_counts) {
  auto encoded = std::vector<std::tuple<uint8_t, uint64_t>>{};
  encoded.reserve(intent_status_counts.size());
  for (const auto& [status, count] : intent_status_counts) {
    encoded.emplace_back(std::tuple{static_cast<uint8_t>(status), count});
  }
  return encoded;
}

void append_intent_status_metrics(
    const std::map<uint32_t, uint64_t>& intent_status_counts,
    std::vector<std::tuple<std::string, uint64_t>>& numeric) {
  for (const auto& [status, count] : intent_status_counts) {
    numeric.emplace_back(std::tuple{
        "intent_status_" + std::to_string(static_cast<uint32_t>(status)),
        count});
  }
}

charter::schema::query_result_t query_engine_info(
    const query_request_context& request) {
  return make_query_success_result(
      request, request.encoder.encode(std::tuple{
                   request.last_committed_height,
                   request.last_committed_state_root, request.chain_id}));
}

charter::schema::query_result_t query_engine_keyspaces(
    const query_request_context& request) {
  auto prefixes = std::vector<std::string>{};
  prefixes.reserve(kEngineKeyspaces.size());
  for (const auto& prefix : kEngineKeyspaces) {
    prefixes.emplace_back(prefix);
  }
  return make_query_success_result(request, request.encoder.encode(prefixes));
}

charter::schema::query_result_t query_metrics_engine(
    const query_request_context& request) {
  if (auto invalid = require_empty_query_key(request, "metrics");
      invalid.has_value()) {
    return *invalid;
  }

  auto observed = collect_engine_observability(request);
  auto degraded_mode = current_degraded_mode(request.storage, request.encoder);
  auto numeric = std::vector<std::tuple<std::string, uint64_t>>{
      {"last_committed_height",
       static_cast<uint64_t>(request.last_committed_height)},
      {"transactions_total", observed.transaction_total},
      {"transactions_failed", observed.transaction_failed},
      {"transactions_succeeded",
       observed.transaction_total - observed.transaction_failed},
      {"security_events_total", observed.security_event_total},
      {"snapshots_total", observed.snapshots_total},
      {"degraded_mode_active",
       degraded_mode == charter::schema::degraded_mode_t::normal ? 0u : 1u},
  };
  for (const auto& [code, count] : observed.transaction_code_counts) {
    numeric.emplace_back(
        std::tuple{"transactions_code_" + std::to_string(code), count});
  }
  for (const auto& [severity, count] : observed.security_severity_counts) {
    numeric.emplace_back(
        std::tuple{"security_events_severity_" +
                       std::to_string(static_cast<uint32_t>(severity)),
                   count});
  }
  append_intent_status_metrics(observed.intent_status_counts, numeric);

  auto labels = std::vector<std::tuple<std::string, std::string>>{
      {"chain_id", hash_to_hex_string(request.chain_id)},
      {"state_root", hash_to_hex_string(request.last_committed_state_root)},
      {"degraded_mode", std::string{to_string(degraded_mode)}},
  };
  return make_query_success_result(request, request.encoder.encode(std::tuple{
                                                uint16_t{1}, numeric, labels}));
}

charter::schema::query_result_t query_explorer_overview(
    const query_request_context& request) {
  if (auto invalid = require_empty_query_key(request, "explorer overview");
      invalid.has_value()) {
    return *invalid;
  }

  auto observed = collect_engine_observability(request);
  auto intent_status_counts =
      encode_intent_status_counts(observed.intent_status_counts);
  auto degraded_mode = current_degraded_mode(request.storage, request.encoder);
  return make_query_success_result(
      request,
      request.encoder.encode(std::tuple{
          uint16_t{1}, static_cast<uint64_t>(request.last_committed_height),
          request.last_committed_state_root, request.chain_id,
          observed.transaction_total, observed.transaction_failed,
          observed.security_event_total, observed.snapshots_total,
          intent_status_counts, static_cast<uint8_t>(degraded_mode)}));
}

charter::schema::query_result_t query_state_workspace(
    const query_request_context& request) {
  if (request.data.size() != 32) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key size", "workspace query key must be 32 bytes");
  }
  auto workspace_id = charter::schema::hash32_t{};
  std::copy_n(std::begin(request.data), workspace_id.size(),
              std::begin(workspace_id));
  auto key = make_workspace_key(request.encoder, workspace_id);
  auto workspace = request.storage.get<charter::schema::workspace_state_t>(
      request.encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  if (!workspace) {
    return make_query_error_result(request,
                                   charter::schema::query_error_code::not_found,
                                   "not found", "workspace not found");
  }
  return make_query_success_result(request, request.encoder.encode(*workspace));
}

charter::schema::query_result_t query_state_vault(
    const query_request_context& request) {
  auto decoded = request.encoder.try_decode<
      std::tuple<charter::schema::hash32_t, charter::schema::hash32_t>>(
      request.data);
  if (!decoded) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key encoding",
        "vault query key must decode to (workspace_id,vault_id)");
  }
  auto workspace_id = std::get<0>(decoded.value());
  auto vault_id = std::get<1>(decoded.value());
  auto key = make_vault_key(request.encoder, workspace_id, vault_id);
  auto vault = request.storage.get<charter::schema::vault_state_t>(
      request.encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  if (!vault) {
    return make_query_error_result(request,
                                   charter::schema::query_error_code::not_found,
                                   "not found", "vault not found");
  }
  return make_query_success_result(request, request.encoder.encode(*vault));
}

charter::schema::query_result_t query_state_asset(
    const query_request_context& request) {
  if (request.data.size() != 32) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key size", "asset query key must be 32 bytes");
  }
  auto asset_id = charter::schema::hash32_t{};
  std::copy_n(std::begin(request.data), asset_id.size(), std::begin(asset_id));
  auto key = make_asset_key(request.encoder, asset_id);
  auto asset = request.storage.get<charter::schema::asset_state_t>(
      request.encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  if (!asset) {
    return make_query_error_result(request,
                                   charter::schema::query_error_code::not_found,
                                   "not found", "asset not found");
  }
  return make_query_success_result(request, request.encoder.encode(*asset));
}

charter::schema::query_result_t query_state_destination(
    const query_request_context& request) {
  auto decoded = request.encoder.try_decode<
      std::tuple<charter::schema::hash32_t, charter::schema::hash32_t>>(
      request.data);
  if (!decoded) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key encoding",
        "destination query key must decode to (workspace_id,destination_id)");
  }
  auto key = make_destination_key(request.encoder, std::get<0>(decoded.value()),
                                  std::get<1>(decoded.value()));
  auto destination = request.storage.get<charter::schema::destination_state_t>(
      request.encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  if (!destination) {
    return make_query_error_result(request,
                                   charter::schema::query_error_code::not_found,
                                   "not found", "destination not found");
  }
  return make_query_success_result(request,
                                   request.encoder.encode(*destination));
}

charter::schema::query_result_t query_state_policy_set(
    const query_request_context& request) {
  auto decoded =
      request.encoder
          .try_decode<std::tuple<charter::schema::hash32_t, uint32_t>>(
              request.data);
  if (!decoded) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key encoding",
        "policy_set query key must decode to (policy_set_id,policy_version)");
  }
  auto key = make_policy_set_key(request.encoder, std::get<0>(decoded.value()),
                                 std::get<1>(decoded.value()));
  auto policy = request.storage.get<charter::schema::policy_set_state_t>(
      request.encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  if (!policy) {
    return make_query_error_result(request,
                                   charter::schema::query_error_code::not_found,
                                   "not found", "policy set not found");
  }
  return make_query_success_result(request, request.encoder.encode(*policy));
}

charter::schema::query_result_t query_state_active_policy(
    const query_request_context& request) {
  auto decoded =
      request.encoder.try_decode<charter::schema::policy_scope_t>(request.data);
  if (!decoded) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key encoding",
        "active_policy query key must decode to policy_scope");
  }
  auto key = make_active_policy_key(request.encoder, decoded.value());
  auto active = request.storage.get<charter::schema::active_policy_pointer_t>(
      request.encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  if (!active) {
    return make_query_error_result(request,
                                   charter::schema::query_error_code::not_found,
                                   "not found", "active policy not found");
  }
  return make_query_success_result(request, request.encoder.encode(*active));
}

charter::schema::query_result_t query_state_intent(
    const query_request_context& request) {
  auto decoded = request.encoder.try_decode<
      std::tuple<charter::schema::hash32_t, charter::schema::hash32_t,
                 charter::schema::hash32_t>>(request.data);
  if (!decoded) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key encoding",
        "intent query key must decode to (workspace_id,vault_id,intent_id)");
  }
  auto key = make_intent_key(request.encoder, std::get<0>(decoded.value()),
                             std::get<1>(decoded.value()),
                             std::get<2>(decoded.value()));
  auto intent = request.storage.get<charter::schema::intent_state_t>(
      request.encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  if (!intent) {
    return make_query_error_result(request,
                                   charter::schema::query_error_code::not_found,
                                   "not found", "intent not found");
  }
  return make_query_success_result(request, request.encoder.encode(*intent));
}

charter::schema::query_result_t query_state_approval(
    const query_request_context& request) {
  auto decoded = request.encoder.try_decode<
      std::tuple<charter::schema::hash32_t, charter::schema::signer_id_t>>(
      request.data);
  if (!decoded) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key encoding",
        "approval query key must decode to (intent_id,signer)");
  }
  auto key = make_approval_key(request.encoder, std::get<0>(decoded.value()),
                               std::get<1>(decoded.value()));
  auto approval = request.storage.get<charter::schema::approval_state_t>(
      request.encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  if (!approval) {
    return make_query_error_result(request,
                                   charter::schema::query_error_code::not_found,
                                   "not found", "approval not found");
  }
  return make_query_success_result(request, request.encoder.encode(*approval));
}

charter::schema::query_result_t query_state_attestation(
    const query_request_context& request) {
  auto decoded = request.encoder.try_decode<
      std::tuple<charter::schema::hash32_t, charter::schema::hash32_t,
                 charter::schema::claim_type_t, charter::schema::signer_id_t>>(
      request.data);
  if (!decoded) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key encoding",
        "attestation query key must decode to "
        "(workspace_id,subject,claim,issuer)");
  }
  auto key = make_attestation_key(request.encoder, std::get<0>(decoded.value()),
                                  std::get<1>(decoded.value()),
                                  std::get<2>(decoded.value()),
                                  std::get<3>(decoded.value()));
  auto record = request.storage.get<charter::schema::attestation_record_t>(
      request.encoder, charter::schema::bytes_view_t{key.data(), key.size()});
  if (!record) {
    return make_query_error_result(request,
                                   charter::schema::query_error_code::not_found,
                                   "not found", "attestation not found");
  }
  return make_query_success_result(request, request.encoder.encode(*record));
}

charter::schema::query_result_t query_state_role_assignment(
    const query_request_context& request) {
  auto decoded = request.encoder.try_decode<
      std::tuple<charter::schema::policy_scope_t, charter::schema::signer_id_t,
                 charter::schema::role_id_t>>(request.data);
  if (!decoded) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key encoding",
        "role_assignment query key must decode to (scope,subject,role)");
  }
  auto key = make_role_assignment_key(
      request.encoder, std::get<0>(decoded.value()),
      std::get<1>(decoded.value()), std::get<2>(decoded.value()));
  auto role_assignment =
      request.storage.get<charter::schema::role_assignment_state_t>(
          request.encoder,
          charter::schema::bytes_view_t{key.data(), key.size()});
  if (!role_assignment) {
    return make_query_error_result(request,
                                   charter::schema::query_error_code::not_found,
                                   "not found", "role assignment not found");
  }
  return make_query_success_result(request,
                                   request.encoder.encode(*role_assignment));
}

charter::schema::query_result_t query_state_signer_quarantine(
    const query_request_context& request) {
  auto decoded =
      request.encoder.try_decode<charter::schema::signer_id_t>(request.data);
  if (!decoded) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key encoding",
        "signer_quarantine query key must decode to signer_id_t");
  }
  auto key = make_signer_quarantine_key(request.encoder, decoded.value());
  auto quarantine =
      request.storage.get<charter::schema::signer_quarantine_state_t>(
          request.encoder,
          charter::schema::bytes_view_t{key.data(), key.size()});
  if (!quarantine) {
    return make_query_error_result(request,
                                   charter::schema::query_error_code::not_found,
                                   "not found", "signer quarantine not found");
  }
  return make_query_success_result(request,
                                   request.encoder.encode(*quarantine));
}

charter::schema::query_result_t query_state_degraded_mode(
    const query_request_context& request) {
  auto mode = load_degraded_mode_state(request.storage, request.encoder);
  if (!mode) {
    return make_query_success_result(
        request,
        request.encoder.encode(charter::schema::degraded_mode_state_t{}));
  }
  return make_query_success_result(request, request.encoder.encode(*mode));
}

charter::schema::query_result_t query_state_destination_update(
    const query_request_context& request) {
  auto decoded = request.encoder.try_decode<
      std::tuple<charter::schema::hash32_t, charter::schema::hash32_t,
                 charter::schema::hash32_t>>(request.data);
  if (!decoded) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key encoding",
        "destination_update key must decode to "
        "(workspace_id,destination_id,update_id)");
  }
  auto key = make_destination_update_key(
      request.encoder, std::get<0>(decoded.value()),
      std::get<1>(decoded.value()), std::get<2>(decoded.value()));
  auto update =
      request.storage.get<charter::schema::destination_update_state_t>(
          request.encoder,
          charter::schema::bytes_view_t{key.data(), key.size()});
  if (!update) {
    return make_query_error_result(request,
                                   charter::schema::query_error_code::not_found,
                                   "not found", "destination update not found");
  }
  return make_query_success_result(request, request.encoder.encode(*update));
}

charter::schema::query_result_t query_history_range(
    const query_request_context& request) {
  auto decoded =
      request.encoder.try_decode<std::tuple<uint64_t, uint64_t>>(request.data);
  if (!decoded) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key encoding",
        "history range query requires SCALE tuple(from_height,to_height)");
  }
  auto from_height = std::get<0>(decoded.value());
  auto to_height = std::get<1>(decoded.value());
  auto encoded_rows = std::vector<
      std::tuple<uint64_t, uint32_t, uint32_t, charter::schema::bytes_t>>{};
  for_each_history_row(
      request.storage, request.encoder,
      [&](uint64_t height, uint32_t index, uint32_t code,
          const charter::schema::bytes_t& tx_bytes) {
        if (height < from_height || height > to_height) {
          return;
        }
        encoded_rows.emplace_back(std::tuple{height, index, code, tx_bytes});
      });
  return make_query_success_result(request,
                                   request.encoder.encode(encoded_rows));
}

charter::schema::query_result_t query_history_export(
    const query_request_context& request) {
  auto state_prefixes = make_state_prefixes(request.encoder);
  auto history_prefix = make_prefix_key(request.encoder, kHistoryPrefix);
  auto snapshot_prefix = charter::schema::make_bytes(kSnapshotPrefix);
  auto state = list_state_entries(request.storage, state_prefixes);
  auto history_rows =
      request.storage.list_by_prefix(charter::schema::bytes_view_t{
          history_prefix.data(), history_prefix.size()});
  auto snapshots = request.storage.list_by_prefix(charter::schema::bytes_view_t{
      snapshot_prefix.data(), snapshot_prefix.size()});
  auto committed = request.storage.load_committed_state(request.encoder);
  return make_query_success_result(
      request, request.encoder.encode(std::tuple{uint16_t{1}, committed, state,
                                                 history_rows, snapshots,
                                                 request.chain_id}));
}

charter::schema::query_result_t query_events_range(
    const query_request_context& request) {
  auto decoded =
      request.encoder.try_decode<std::tuple<uint64_t, uint64_t>>(request.data);
  if (!decoded) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key encoding",
        "events range query requires SCALE tuple(from_id,to_id)");
  }
  auto from_id = std::get<0>(decoded.value());
  auto to_id = std::get<1>(decoded.value());
  auto prefix = make_prefix_key(request.encoder, kEventPrefix);
  auto rows = request.storage.list_by_prefix(
      charter::schema::bytes_view_t{prefix.data(), prefix.size()});
  auto events = std::vector<charter::schema::security_event_record_t>{};
  for (const auto& [key, value] : rows) {
    auto parsed = parse_event_key(
        request.encoder, charter::schema::bytes_view_t{key.data(), key.size()});
    if (!parsed.has_value() || parsed.value() < from_id ||
        parsed.value() > to_id) {
      continue;
    }
    auto event =
        request.encoder.try_decode<charter::schema::security_event_record_t>(
            charter::schema::bytes_view_t{value.data(), value.size()});
    if (event.has_value()) {
      events.emplace_back(event.value());
    }
  }
  return make_query_success_result(request, request.encoder.encode(events));
}

charter::schema::query_result_t query_explorer_block(
    const query_request_context& request) {
  auto decoded = request.encoder.try_decode<uint64_t>(request.data);
  if (!decoded.has_value()) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key encoding",
        "explorer block query requires SCALE uint64 block height");
  }
  auto block_height = decoded.value();
  auto rows = std::vector<std::tuple<uint32_t, uint32_t, std::string,
                                     std::string, uint64_t, std::string>>{};
  for_each_history_row(
      request.storage, request.encoder,
      [&](uint64_t height, uint32_t index, uint32_t code,
          const charter::schema::bytes_t& tx_bytes) {
        if (height != block_height) {
          return;
        }
        auto transaction =
            make_explorer_transaction_summary(request.encoder, tx_bytes);
        rows.emplace_back(std::tuple{
            index, code, transaction.transaction_hash_hex,
            transaction.transaction.payload_name, transaction.transaction.nonce,
            transaction.transaction.signer_hex});
      });
  std::ranges::sort(rows, [](const auto& lhs, const auto& rhs) {
    return std::get<0>(lhs) < std::get<0>(rhs);
  });
  return make_query_success_result(
      request, request.encoder.encode(std::tuple{block_height, rows}));
}

charter::schema::query_result_t query_explorer_transaction(
    const query_request_context& request) {
  auto decoded =
      request.encoder.try_decode<std::tuple<uint64_t, uint32_t>>(request.data);
  if (!decoded.has_value()) {
    return make_query_error_result(
        request, charter::schema::query_error_code::invalid_key,
        "invalid key encoding",
        "explorer transaction query requires SCALE tuple(height,index)");
  }
  auto height = std::get<0>(decoded.value());
  auto index = std::get<1>(decoded.value());
  auto key = make_history_key(request.encoder, height, index);
  auto row =
      request.storage.get<std::tuple<uint32_t, charter::schema::bytes_t>>(
          request.encoder,
          charter::schema::bytes_view_t{key.data(), key.size()});
  if (!row.has_value()) {
    return make_query_error_result(
        request, charter::schema::query_error_code::not_found, "not found",
        "history row not found for requested (height,index)");
  }

  auto code = std::get<0>(row.value());
  auto tx_bytes = std::get<1>(row.value());
  auto transaction =
      make_explorer_transaction_summary(request.encoder, tx_bytes);
  return make_query_success_result(
      request,
      request.encoder.encode(std::tuple{
          uint16_t{1}, height, index, code, transaction.transaction_hash_hex,
          transaction.transaction.payload_name, transaction.transaction.nonce,
          transaction.transaction.signer_hex, tx_bytes}));
}

charter::schema::query_result_t query_unsupported_path(
    const query_request_context& request) {
  return make_query_error_result(
      request, charter::schema::query_error_code::unsupported_path,
      "unsupported path",
      "supported paths: /engine/info, /state/workspace, /state/vault, "
      "/state/asset, /state/destination, /state/policy_set, "
      "/state/active_policy, "
      "/state/intent, /state/approval, /state/attestation, "
      "/state/role_assignment, "
      "/state/signer_quarantine, /state/degraded_mode, "
      "/state/destination_update, "
      "/history/range, /history/export, /events/range, /engine/keyspaces, "
      "/metrics/engine, /explorer/overview, /explorer/block, "
      "/explorer/transaction");
}

using query_handler_t =
    charter::schema::query_result_t (*)(const query_request_context&);

struct query_route_t final {
  std::string_view path;
  query_handler_t handler;
};

const auto kQueryRoutes = std::array{
    query_route_t{"/engine/info", query_engine_info},
    query_route_t{"/engine/keyspaces", query_engine_keyspaces},
    query_route_t{"/metrics/engine", query_metrics_engine},
    query_route_t{"/explorer/overview", query_explorer_overview},
    query_route_t{"/explorer/block", query_explorer_block},
    query_route_t{"/explorer/transaction", query_explorer_transaction},
    query_route_t{"/state/workspace", query_state_workspace},
    query_route_t{"/state/vault", query_state_vault},
    query_route_t{"/state/asset", query_state_asset},
    query_route_t{"/state/destination", query_state_destination},
    query_route_t{"/state/policy_set", query_state_policy_set},
    query_route_t{"/state/active_policy", query_state_active_policy},
    query_route_t{"/state/intent", query_state_intent},
    query_route_t{"/state/approval", query_state_approval},
    query_route_t{"/state/attestation", query_state_attestation},
    query_route_t{"/state/role_assignment", query_state_role_assignment},
    query_route_t{"/state/signer_quarantine", query_state_signer_quarantine},
    query_route_t{"/state/degraded_mode", query_state_degraded_mode},
    query_route_t{"/state/destination_update", query_state_destination_update},
    query_route_t{"/history/range", query_history_range},
    query_route_t{"/history/export", query_history_export},
    query_route_t{"/events/range", query_events_range},
};

charter::schema::transaction_result_t make_execute_error(
    charter::schema::transaction_error_code code,
    std::string log,
    std::string info) {
  return make_error_transaction_result(code, std::move(log), std::move(info),
                                       std::string{kExecuteCodespace});
}

charter::schema::transaction_result_t make_execute_success(std::string info) {
  auto result = charter::schema::transaction_result_t{};
  result.info = std::move(info);
  return result;
}

template <typename Encoder>
charter::schema::transaction_result_t execute_create_workspace_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::create_workspace_t& operation) {
  auto workspace_key = make_workspace_key(encoder, operation.workspace_id);
  if (workspace_exists(storage, encoder, operation.workspace_id)) {
    return make_execute_error(
        charter::schema::transaction_error_code::workspace_exists,
        "workspace already exists", "workspace_id already present");
  }

  storage.put(
      encoder,
      charter::schema::bytes_view_t{workspace_key.data(), workspace_key.size()},
      charter::schema::workspace_state_t{operation});

  auto scope =
      charter::schema::policy_scope_t{charter::schema::workspace_scope_t{
          .workspace_id = operation.workspace_id}};
  for (const auto& admin : operation.admin_set) {
    auto role_key = make_role_assignment_key(encoder, scope, admin,
                                             charter::schema::role_id_t::admin);
    storage.put(encoder,
                charter::schema::bytes_view_t{role_key.data(), role_key.size()},
                charter::schema::role_assignment_state_t{
                    .scope = scope,
                    .subject = admin,
                    .role = charter::schema::role_id_t::admin,
                    .enabled = true,
                    .not_before = std::nullopt,
                    .expires_at = std::nullopt,
                    .note = std::nullopt});
  }

  return make_execute_success("create_workspace persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t execute_create_vault_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::create_vault_t& operation) {
  auto workspace =
      load_workspace_state(storage, encoder, operation.workspace_id);
  if (!workspace.has_value()) {
    return make_execute_error(
        charter::schema::transaction_error_code::workspace_missing,
        "workspace missing", "workspace must exist before vault creation");
  }

  auto vault_key =
      make_vault_key(encoder, operation.workspace_id, operation.vault_id);
  if (vault_exists(storage, encoder, operation.workspace_id,
                   operation.vault_id)) {
    return make_execute_error(
        charter::schema::transaction_error_code::vault_exists,
        "vault already exists", "vault_id already present");
  }

  auto vault_state = charter::schema::vault_state_t{operation};
  if (workspace->jurisdiction.has_value()) {
    if (vault_state.jurisdiction.has_value() &&
        vault_state.jurisdiction->jurisdiction_id !=
            workspace->jurisdiction->jurisdiction_id) {
      return make_execute_error(
          charter::schema::transaction_error_code::jurisdiction_mismatch,
          "jurisdiction mismatch",
          "vault jurisdiction must match workspace jurisdiction");
    }
    if (!vault_state.jurisdiction.has_value()) {
      vault_state.jurisdiction = workspace->jurisdiction;
    }
  }

  storage.put(encoder,
              charter::schema::bytes_view_t{vault_key.data(), vault_key.size()},
              vault_state);
  return make_execute_success("create_vault persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t execute_upsert_destination_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::upsert_destination_t& operation) {
  if (!workspace_exists(storage, encoder, operation.workspace_id)) {
    return make_execute_error(
        charter::schema::transaction_error_code::workspace_missing,
        "workspace missing", "workspace must exist before destination upsert");
  }

  auto destination_key = make_destination_key(encoder, operation.workspace_id,
                                              operation.destination_id);
  storage.put(encoder,
              charter::schema::bytes_view_t{destination_key.data(),
                                            destination_key.size()},
              charter::schema::destination_state_t{operation});
  return make_execute_success("upsert_destination persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t execute_upsert_asset_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::upsert_asset_t& operation) {
  auto asset_key = make_asset_key(encoder, operation.asset_id);
  storage.put(encoder,
              charter::schema::bytes_view_t{asset_key.data(), asset_key.size()},
              charter::schema::asset_state_t{operation});
  return make_execute_success("upsert_asset persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t execute_disable_asset_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::disable_asset_t& operation) {
  auto asset = load_asset_state(storage, encoder, operation.asset_id);
  if (!asset.has_value()) {
    return make_execute_error(
        charter::schema::transaction_error_code::asset_missing, "asset missing",
        "asset must be onboarded before use");
  }
  asset->enabled = false;
  auto asset_key = make_asset_key(encoder, operation.asset_id);
  storage.put(encoder,
              charter::schema::bytes_view_t{asset_key.data(), asset_key.size()},
              *asset);
  return make_execute_success("disable_asset persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t execute_create_policy_set_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::create_policy_set_t& operation) {
  if (!policy_scope_exists(storage, encoder, operation.scope)) {
    return make_execute_error(
        charter::schema::transaction_error_code::policy_scope_missing,
        "policy scope missing", "scope target does not exist");
  }

  auto policy_key =
      make_policy_set_key(encoder, operation.policy_set_id,
                          static_cast<uint32_t>(operation.policy_version));
  auto existing = storage.get<charter::schema::policy_set_state_t>(
      encoder,
      charter::schema::bytes_view_t{policy_key.data(), policy_key.size()});
  if (existing) {
    return make_execute_error(
        charter::schema::transaction_error_code::policy_set_exists,
        "policy set already exists", "policy_set_id/version already present");
  }

  storage.put(
      encoder,
      charter::schema::bytes_view_t{policy_key.data(), policy_key.size()},
      charter::schema::policy_set_state_t{operation});
  return make_execute_success("create_policy_set persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t execute_activate_policy_set_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::activate_policy_set_t& operation) {
  if (!policy_scope_exists(storage, encoder, operation.scope)) {
    return make_execute_error(
        charter::schema::transaction_error_code::policy_scope_missing,
        "policy scope missing", "scope target does not exist");
  }

  auto policy_key = make_policy_set_key(encoder, operation.policy_set_id,
                                        operation.policy_set_version);
  auto policy = storage.get<charter::schema::policy_set_state_t>(
      encoder,
      charter::schema::bytes_view_t{policy_key.data(), policy_key.size()});
  if (!policy) {
    return make_execute_error(
        charter::schema::transaction_error_code::policy_set_missing,
        "policy set missing", "cannot activate missing policy");
  }

  auto active_key = make_active_policy_key(encoder, operation.scope);
  storage.put(
      encoder,
      charter::schema::bytes_view_t{active_key.data(), active_key.size()},
      charter::schema::active_policy_pointer_t{
          .policy_set_id = operation.policy_set_id,
          .policy_set_version = operation.policy_set_version});
  return make_execute_success("activate_policy_set persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t validate_transfer_action_asset_onboarding(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::intent_action_t& action) {
  auto result = charter::schema::transaction_result_t{};
  std::visit(
      overloaded{[&](const charter::schema::transfer_parameters_t& transfer) {
        auto asset = load_asset_state(storage, encoder, transfer.asset_id);
        if (!asset.has_value()) {
          result = make_execute_error(
              charter::schema::transaction_error_code::asset_missing,
              "asset missing", "asset must be onboarded before use");
          return;
        }
        if (!asset->enabled) {
          result = make_execute_error(
              charter::schema::transaction_error_code::asset_disabled,
              "asset disabled", "asset is disabled");
          return;
        }
      }},
      action);
  return result;
}

template <typename Encoder>
charter::schema::transaction_result_t execute_propose_intent_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::propose_intent_t& operation,
    const charter::schema::signer_id_t& signer,
    const uint64_t now_ms,
    std::map<uint32_t, uint64_t>& intent_status_counts) {
  // Proposal stage freezes initial policy snapshot information on the intent
  // and performs early checks that can fail fast before approvals accumulate.
  if (!workspace_exists(storage, encoder, operation.workspace_id) ||
      !vault_exists(storage, encoder, operation.workspace_id,
                    operation.vault_id)) {
    return make_execute_error(
        charter::schema::transaction_error_code::vault_scope_missing,
        "vault scope missing", "workspace/vault must exist");
  }

  auto scope = charter::schema::policy_scope_t{charter::schema::vault_t{
      .workspace_id = operation.workspace_id, .vault_id = operation.vault_id}};
  if (!active_policy_exists(storage, encoder, scope)) {
    return make_execute_error(
        charter::schema::transaction_error_code::active_policy_missing,
        "active policy missing", "activate a policy before intents");
  }

  auto intent_key = make_intent_key(encoder, operation.workspace_id,
                                    operation.vault_id, operation.intent_id);
  auto existing = storage.get<charter::schema::intent_state_t>(
      encoder,
      charter::schema::bytes_view_t{intent_key.data(), intent_key.size()});
  if (existing) {
    return make_execute_error(
        charter::schema::transaction_error_code::intent_exists,
        "intent already exists", "intent_id already present");
  }

  auto requirements = resolve_policy_requirements(
      storage, encoder, scope,
      operation_type_from_intent_action(operation.action));
  if (!requirements) {
    return make_execute_error(
        charter::schema::transaction_error_code::policy_resolution_failed,
        "policy resolution failed", "active policy pointer is invalid");
  }

  auto asset_result = validate_transfer_action_asset_onboarding(
      storage, encoder, operation.action);
  if (asset_result.code != 0) {
    return asset_result;
  }

  auto result = charter::schema::transaction_result_t{};
  std::visit(
      overloaded{[&](const charter::schema::transfer_parameters_t& action) {
        // Per-transaction cap check.
        if (requirements->per_transaction_limit.has_value() &&
            charter::schema::amount_t{action.amount} >
                requirements->per_transaction_limit.value()) {
          result = make_execute_error(
              charter::schema::transaction_error_code::limit_exceeded,
              "limit exceeded",
              "transfer amount exceeds per-transaction policy limit");
          return;
        }
        if (requirements->require_whitelisted_destination &&
            !destination_enabled(storage, encoder, operation.workspace_id,
                                 action.destination_id)) {
          // Destination must already be present+enabled when whitelist is
          // required by policy.
          result =
              make_execute_error(charter::schema::transaction_error_code::
                                     destination_not_whitelisted,
                                 "destination not whitelisted",
                                 "destination must be enabled in whitelist");
          return;
        }
      }},
      operation.action);
  if (result.code != 0) {
    return result;
  }

  if (!enforce_velocity_limits(storage, encoder, operation.workspace_id,
                               operation.vault_id, operation.action,
                               requirements->velocity_limits, now_ms, result,
                               kExecuteCodespace)) {
    return result;
  }

  auto required_threshold = requirements->threshold;
  auto delay_ms = requirements->delay_ms;
  // not_before encodes timelock from merged policy rules.
  auto not_before = now_ms + delay_ms;
  auto status = charter::schema::intent_status_t::pending_approval;
  if (required_threshold == 0 && now_ms >= not_before) {
    status = charter::schema::intent_status_t::executable;
  }

  auto state = charter::schema::intent_state_t{
      .workspace_id = operation.workspace_id,
      .vault_id = operation.vault_id,
      .intent_id = operation.intent_id,
      .created_by = signer,
      .created_at = now_ms,
      .not_before = not_before,
      .expires_at = operation.expires_at,
      .action = operation.action,
      .status = status,
      .policy_set_id = requirements->policy_set_id,
      .policy_version = requirements->policy_version,
      .required_threshold = required_threshold,
      .approvals_count = 0,
      // Claim requirements are copied onto intent state at proposal time.
      .claim_requirements = requirements->claim_requirements};
  put_intent_state_with_counters(storage, encoder, intent_key, std::nullopt,
                                 state, intent_status_counts);
  return make_execute_success("propose_intent persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t execute_approve_intent_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::approve_intent_t& operation,
    const charter::schema::signer_id_t& signer,
    const uint64_t now_ms,
    std::map<uint32_t, uint64_t>& intent_status_counts) {
  // Approval stage records signer vote and updates intent readiness state.
  if (!workspace_exists(storage, encoder, operation.workspace_id) ||
      !vault_exists(storage, encoder, operation.workspace_id,
                    operation.vault_id)) {
    return make_execute_error(
        charter::schema::transaction_error_code::vault_scope_missing,
        "vault scope missing", "workspace/vault must exist");
  }

  auto intent_key = make_intent_key(encoder, operation.workspace_id,
                                    operation.vault_id, operation.intent_id);
  auto intent = storage.get<charter::schema::intent_state_t>(
      encoder,
      charter::schema::bytes_view_t{intent_key.data(), intent_key.size()});
  if (!intent) {
    return make_execute_error(
        charter::schema::transaction_error_code::intent_missing,
        "intent missing", "intent must exist before approval");
  }
  if (intent->status == charter::schema::intent_status_t::executed ||
      intent->status == charter::schema::intent_status_t::cancelled) {
    return make_execute_error(
        charter::schema::transaction_error_code::intent_not_approvable,
        "intent not approvable", "intent already finalized");
  }

  if (intent->expires_at.has_value() && now_ms > intent->expires_at.value()) {
    auto previous_status = intent->status;
    intent->status = charter::schema::intent_status_t::expired;
    put_intent_state_with_counters(storage, encoder, intent_key,
                                   previous_status, *intent,
                                   intent_status_counts);
    return make_execute_error(
        charter::schema::transaction_error_code::intent_expired,
        "intent expired", "intent can no longer be approved");
  }

  auto approval_key = make_approval_key(encoder, operation.intent_id, signer);
  auto approval_existing = storage.get<charter::schema::approval_state_t>(
      encoder,
      charter::schema::bytes_view_t{approval_key.data(), approval_key.size()});
  if (approval_existing) {
    return make_execute_error(
        charter::schema::transaction_error_code::duplicate_approval,
        "duplicate approval", "signer already approved this intent");
  }

  auto scope = charter::schema::policy_scope_t{charter::schema::vault_t{
      .workspace_id = operation.workspace_id, .vault_id = operation.vault_id}};
  auto requirements = resolve_policy_requirements(
      storage, encoder, scope,
      operation_type_from_intent_action(intent->action));
  if (!requirements) {
    return make_execute_error(
        charter::schema::transaction_error_code::policy_resolution_failed,
        "policy resolution failed", "active policy pointer is invalid");
  }
  if (requirements->require_distinct_from_initiator &&
      signer_ids_equal(encoder, intent->created_by, signer)) {
    return make_execute_error(
        charter::schema::transaction_error_code::separation_of_duties_violated,
        "separation of duties violated",
        "approver must be distinct from intent initiator");
  }

  storage.put(
      encoder,
      charter::schema::bytes_view_t{approval_key.data(), approval_key.size()},
      charter::schema::approval_state_t{.intent_id = operation.intent_id,
                                        .signer = signer,
                                        .signed_at = now_ms});

  auto previous_status = intent->status;
  intent->approvals_count += 1;
  // Intent becomes executable only when both threshold and timelock are met.
  if (intent->approvals_count >= intent->required_threshold &&
      now_ms >= intent->not_before) {
    intent->status = charter::schema::intent_status_t::executable;
  } else {
    intent->status = charter::schema::intent_status_t::pending_approval;
  }
  put_intent_state_with_counters(storage, encoder, intent_key, previous_status,
                                 *intent, intent_status_counts);
  return make_execute_success("approve_intent persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t execute_cancel_intent_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::cancel_intent_t& operation,
    std::map<uint32_t, uint64_t>& intent_status_counts) {
  if (!workspace_exists(storage, encoder, operation.workspace_id) ||
      !vault_exists(storage, encoder, operation.workspace_id,
                    operation.vault_id)) {
    return make_execute_error(
        charter::schema::transaction_error_code::vault_scope_missing,
        "vault scope missing", "workspace/vault must exist");
  }

  auto intent_key = make_intent_key(encoder, operation.workspace_id,
                                    operation.vault_id, operation.intent_id);
  auto intent = storage.get<charter::schema::intent_state_t>(
      encoder,
      charter::schema::bytes_view_t{intent_key.data(), intent_key.size()});
  if (!intent) {
    return make_execute_error(
        charter::schema::transaction_error_code::intent_missing,
        "intent missing", "intent must exist before cancel");
  }
  if (intent->status == charter::schema::intent_status_t::executed) {
    return make_execute_error(
        charter::schema::transaction_error_code::intent_already_executed,
        "intent already executed", "executed intent cannot be cancelled");
  }

  auto previous_status = intent->status;
  intent->status = charter::schema::intent_status_t::cancelled;
  put_intent_state_with_counters(storage, encoder, intent_key, previous_status,
                                 *intent, intent_status_counts);
  return make_execute_success("cancel_intent persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t execute_execute_intent_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::execute_intent_t& operation,
    const charter::schema::signer_id_t& signer,
    const uint64_t now_ms,
    std::map<uint32_t, uint64_t>& intent_status_counts) {
  // Execution stage revalidates dynamic controls before final state transition.
  if (!workspace_exists(storage, encoder, operation.workspace_id) ||
      !vault_exists(storage, encoder, operation.workspace_id,
                    operation.vault_id)) {
    return make_execute_error(
        charter::schema::transaction_error_code::vault_scope_missing,
        "vault scope missing", "workspace/vault must exist");
  }

  auto intent_key = make_intent_key(encoder, operation.workspace_id,
                                    operation.vault_id, operation.intent_id);
  auto intent = storage.get<charter::schema::intent_state_t>(
      encoder,
      charter::schema::bytes_view_t{intent_key.data(), intent_key.size()});
  if (!intent) {
    return make_execute_error(
        charter::schema::transaction_error_code::intent_missing,
        "intent missing", "intent must exist before execution");
  }
  if (intent->expires_at.has_value() && now_ms > intent->expires_at.value()) {
    auto previous_status = intent->status;
    intent->status = charter::schema::intent_status_t::expired;
    put_intent_state_with_counters(storage, encoder, intent_key,
                                   previous_status, *intent,
                                   intent_status_counts);
    return make_execute_error(
        charter::schema::transaction_error_code::intent_expired,
        "intent expired", "intent can no longer be executed");
  }
  if (intent->approvals_count < intent->required_threshold ||
      now_ms < intent->not_before) {
    return make_execute_error(
        charter::schema::transaction_error_code::intent_not_executable,
        "intent not executable", "threshold/timelock requirements not met");
  }

  auto scope = charter::schema::policy_scope_t{charter::schema::vault_t{
      .workspace_id = operation.workspace_id, .vault_id = operation.vault_id}};
  auto requirements = resolve_policy_requirements(
      storage, encoder, scope,
      operation_type_from_intent_action(intent->action));
  if (!requirements) {
    return make_execute_error(
        charter::schema::transaction_error_code::policy_resolution_failed,
        "policy resolution failed", "active policy pointer is invalid");
  }

  auto asset_result = validate_transfer_action_asset_onboarding(
      storage, encoder, intent->action);
  if (asset_result.code != 0) {
    return asset_result;
  }
  if (requirements->require_distinct_from_executor) {
    // Enforce executor/approver separation by checking for executor approval.
    auto executor_approval_key =
        make_approval_key(encoder, operation.intent_id, signer);
    auto approval_by_executor = storage.get<charter::schema::approval_state_t>(
        encoder, charter::schema::bytes_view_t{executor_approval_key.data(),
                                               executor_approval_key.size()});
    if (approval_by_executor.has_value()) {
      return make_execute_error(
          charter::schema::transaction_error_code::
              separation_of_duties_violated,
          "separation of duties violated",
          "executor must be distinct from approvers for this intent");
    }
  }

  auto result = charter::schema::transaction_result_t{};
  if (!enforce_velocity_limits(storage, encoder, operation.workspace_id,
                               operation.vault_id, intent->action,
                               requirements->velocity_limits, now_ms, result,
                               kExecuteCodespace)) {
    return result;
  }

  // Claim requirements captured on the intent must still be satisfiable now.
  for (const auto& requirement : intent->claim_requirements) {
    if (!attestation_satisfies_requirement(
            storage, encoder, intent->workspace_id, intent->workspace_id,
            requirement, now_ms)) {
      return make_execute_error(
          charter::schema::transaction_error_code::
              claim_requirement_unsatisfied,
          "claim requirement unsatisfied",
          "required attestation claim is missing or expired");
    }
  }

  auto previous_status = intent->status;
  intent->status = charter::schema::intent_status_t::executed;
  put_intent_state_with_counters(storage, encoder, intent_key, previous_status,
                                 *intent, intent_status_counts);
  // Counters mutate only after successful execution state transition.
  apply_velocity_limits(storage, encoder, operation.workspace_id,
                        operation.vault_id, intent->action,
                        requirements->velocity_limits, now_ms);
  return make_execute_success("execute_intent persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t execute_upsert_attestation_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::upsert_attestation_t& operation,
    const uint64_t now_ms) {
  if (!workspace_exists(storage, encoder, operation.workspace_id)) {
    return make_execute_error(charter::schema::transaction_error_code::
                                  workspace_missing_for_operation,
                              "workspace missing", "workspace must exist");
  }

  auto attestation_key =
      make_attestation_key(encoder, operation.workspace_id, operation.subject,
                           operation.claim, operation.issuer);
  storage.put(encoder,
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
  return make_execute_success("upsert_attestation persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t execute_revoke_attestation_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::revoke_attestation_t& operation) {
  if (!workspace_exists(storage, encoder, operation.workspace_id)) {
    return make_execute_error(charter::schema::transaction_error_code::
                                  workspace_missing_for_operation,
                              "workspace missing", "workspace must exist");
  }

  auto attestation_key =
      make_attestation_key(encoder, operation.workspace_id, operation.subject,
                           operation.claim, operation.issuer);
  auto record = storage.get<charter::schema::attestation_record_t>(
      encoder, charter::schema::bytes_view_t{attestation_key.data(),
                                             attestation_key.size()});
  if (!record) {
    return make_execute_error(
        charter::schema::transaction_error_code::attestation_missing,
        "attestation missing", "attestation not found");
  }

  record->status = charter::schema::attestation_status_t::revoked;
  storage.put(encoder,
              charter::schema::bytes_view_t{attestation_key.data(),
                                            attestation_key.size()},
              *record);
  return make_execute_success("revoke_attestation persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t
execute_propose_destination_update_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::propose_destination_update_t& operation,
    const charter::schema::signer_id_t& signer,
    const uint64_t now_ms) {
  if (!workspace_exists(storage, encoder, operation.workspace_id)) {
    return make_execute_error(
        charter::schema::transaction_error_code::workspace_missing,
        "workspace missing", "workspace must exist before destination update");
  }

  auto update_key = make_destination_update_key(encoder, operation.workspace_id,
                                                operation.destination_id,
                                                operation.update_id);
  auto existing = storage.get<charter::schema::destination_update_state_t>(
      encoder,
      charter::schema::bytes_view_t{update_key.data(), update_key.size()});
  if (existing.has_value()) {
    return make_execute_error(
        charter::schema::transaction_error_code::destination_update_exists,
        "destination update exists", "destination update id already present");
  }

  auto state = charter::schema::destination_update_state_t{
      .workspace_id = operation.workspace_id,
      .destination_id = operation.destination_id,
      .update_id = operation.update_id,
      .type = operation.type,
      .chain_type = operation.chain_type,
      .address_or_contract = operation.address_or_contract,
      .enabled = operation.enabled,
      .label = operation.label,
      .created_by = signer,
      .created_at = now_ms,
      .not_before = now_ms + operation.delay_ms,
      .required_approvals = std::max<uint32_t>(1, operation.required_approvals),
      .approvals_count = 0,
      .status = charter::schema::destination_update_status_t::pending_approval};
  storage.put(
      encoder,
      charter::schema::bytes_view_t{update_key.data(), update_key.size()},
      state);
  return make_execute_success("propose_destination_update persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t
execute_approve_destination_update_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::approve_destination_update_t& operation,
    const charter::schema::signer_id_t& signer,
    const uint64_t now_ms) {
  auto update_key = make_destination_update_key(encoder, operation.workspace_id,
                                                operation.destination_id,
                                                operation.update_id);
  auto update = storage.get<charter::schema::destination_update_state_t>(
      encoder,
      charter::schema::bytes_view_t{update_key.data(), update_key.size()});
  if (!update.has_value()) {
    return make_execute_error(
        charter::schema::transaction_error_code::destination_update_missing,
        "destination update missing",
        "destination update must exist before approval");
  }
  if (update->status == charter::schema::destination_update_status_t::applied) {
    return make_execute_error(
        charter::schema::transaction_error_code::destination_update_finalized,
        "destination update finalized", "destination update already applied");
  }

  auto approval_key = make_approval_key(encoder, operation.update_id, signer);
  auto approval_existing = storage.get<charter::schema::approval_state_t>(
      encoder,
      charter::schema::bytes_view_t{approval_key.data(), approval_key.size()});
  if (approval_existing) {
    return make_execute_error(
        charter::schema::transaction_error_code::duplicate_approval,
        "duplicate approval",
        "signer already approved this destination update");
  }

  storage.put(
      encoder,
      charter::schema::bytes_view_t{approval_key.data(), approval_key.size()},
      charter::schema::approval_state_t{.intent_id = operation.update_id,
                                        .signer = signer,
                                        .signed_at = now_ms});
  update->approvals_count += 1;
  if (update->approvals_count >= update->required_approvals &&
      now_ms >= update->not_before) {
    update->status = charter::schema::destination_update_status_t::executable;
  }
  storage.put(
      encoder,
      charter::schema::bytes_view_t{update_key.data(), update_key.size()},
      *update);
  return make_execute_success("approve_destination_update persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t
execute_apply_destination_update_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::apply_destination_update_t& operation,
    const uint64_t now_ms) {
  auto update_key = make_destination_update_key(encoder, operation.workspace_id,
                                                operation.destination_id,
                                                operation.update_id);
  auto update = storage.get<charter::schema::destination_update_state_t>(
      encoder,
      charter::schema::bytes_view_t{update_key.data(), update_key.size()});
  if (!update.has_value()) {
    return make_execute_error(
        charter::schema::transaction_error_code::destination_update_missing,
        "destination update missing",
        "destination update must exist before apply");
  }
  if (update->approvals_count < update->required_approvals ||
      now_ms < update->not_before) {
    return make_execute_error(
        charter::schema::transaction_error_code::
            destination_update_not_executable,
        "destination update not executable",
        "destination update threshold/timelock requirements not met");
  }

  auto destination_key = make_destination_key(encoder, operation.workspace_id,
                                              operation.destination_id);
  storage.put(encoder,
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
  update->status = charter::schema::destination_update_status_t::applied;
  storage.put(
      encoder,
      charter::schema::bytes_view_t{update_key.data(), update_key.size()},
      *update);
  return make_execute_success("apply_destination_update persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t execute_upsert_role_assignment_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::upsert_role_assignment_t& operation,
    const charter::schema::signer_id_t& signer,
    const uint64_t now_ms,
    const uint64_t current_block_height,
    uint64_t& security_event_total,
    std::map<uint32_t, uint64_t>& security_severity_counts) {
  auto role_assignment_key = make_role_assignment_key(
      encoder, operation.scope, operation.subject, operation.role);
  storage.put(encoder,
              charter::schema::bytes_view_t{role_assignment_key.data(),
                                            role_assignment_key.size()},
              charter::schema::role_assignment_state_t{operation});
  append_security_event(
      storage, encoder,
      charter::schema::security_event_type_t::role_assignment_updated,
      charter::schema::security_event_severity_t::info, 0,
      "role assignment updated", signer, std::nullopt, std::nullopt, now_ms,
      current_block_height, &security_event_total, &security_severity_counts);
  return make_execute_success("upsert_role_assignment persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t
execute_upsert_signer_quarantine_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::upsert_signer_quarantine_t& operation,
    const charter::schema::signer_id_t& signer,
    const uint64_t now_ms,
    const uint64_t current_block_height,
    uint64_t& security_event_total,
    std::map<uint32_t, uint64_t>& security_severity_counts) {
  auto quarantine_key = make_signer_quarantine_key(encoder, operation.signer);
  storage.put(encoder,
              charter::schema::bytes_view_t{quarantine_key.data(),
                                            quarantine_key.size()},
              charter::schema::signer_quarantine_state_t{operation});
  append_security_event(
      storage, encoder,
      charter::schema::security_event_type_t::signer_quarantine_updated,
      charter::schema::security_event_severity_t::warning, 0,
      "signer quarantine updated", signer, std::nullopt, std::nullopt, now_ms,
      current_block_height, &security_event_total, &security_severity_counts);
  return make_execute_success("upsert_signer_quarantine persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t execute_set_degraded_mode_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::set_degraded_mode_t& operation,
    const charter::schema::signer_id_t& signer,
    const uint64_t now_ms,
    const uint64_t current_block_height,
    uint64_t& security_event_total,
    std::map<uint32_t, uint64_t>& security_severity_counts) {
  auto mode_key = make_degraded_mode_key(encoder);
  storage.put(encoder,
              charter::schema::bytes_view_t{mode_key.data(), mode_key.size()},
              charter::schema::degraded_mode_state_t{operation});
  append_security_event(
      storage, encoder,
      charter::schema::security_event_type_t::degraded_mode_updated,
      charter::schema::security_event_severity_t::warning, 0,
      "degraded mode updated", signer, std::nullopt, std::nullopt, now_ms,
      current_block_height, &security_event_total, &security_severity_counts);
  return make_execute_success("set_degraded_mode persisted");
}

template <typename Encoder>
charter::schema::transaction_result_t execute_payload_operation(
    rocksdb_storage_t& storage,
    Encoder& encoder,
    const charter::schema::transaction_t& tx,
    const uint64_t now_ms,
    const uint64_t current_block_height,
    std::map<uint32_t, uint64_t>& intent_status_counts,
    uint64_t& security_event_total,
    std::map<uint32_t, uint64_t>& security_severity_counts) {
  // Execution dispatch intentionally stays centralized so the operation matrix
  // is explicit and testable in one location.
  return std::visit(
      overloaded{
          [&](const charter::schema::create_workspace_t& operation) {
            return execute_create_workspace_operation(storage, encoder,
                                                      operation);
          },
          [&](const charter::schema::create_vault_t& operation) {
            return execute_create_vault_operation(storage, encoder, operation);
          },
          [&](const charter::schema::upsert_asset_t& operation) {
            return execute_upsert_asset_operation(storage, encoder, operation);
          },
          [&](const charter::schema::disable_asset_t& operation) {
            return execute_disable_asset_operation(storage, encoder, operation);
          },
          [&](const charter::schema::upsert_destination_t& operation) {
            return execute_upsert_destination_operation(storage, encoder,
                                                        operation);
          },
          [&](const charter::schema::create_policy_set_t& operation) {
            return execute_create_policy_set_operation(storage, encoder,
                                                       operation);
          },
          [&](const charter::schema::activate_policy_set_t& operation) {
            return execute_activate_policy_set_operation(storage, encoder,
                                                         operation);
          },
          [&](const charter::schema::propose_intent_t& operation) {
            return execute_propose_intent_operation(storage, encoder, operation,
                                                    tx.signer, now_ms,
                                                    intent_status_counts);
          },
          [&](const charter::schema::approve_intent_t& operation) {
            return execute_approve_intent_operation(storage, encoder, operation,
                                                    tx.signer, now_ms,
                                                    intent_status_counts);
          },
          [&](const charter::schema::cancel_intent_t& operation) {
            return execute_cancel_intent_operation(storage, encoder, operation,
                                                   intent_status_counts);
          },
          [&](const charter::schema::execute_intent_t& operation) {
            return execute_execute_intent_operation(storage, encoder, operation,
                                                    tx.signer, now_ms,
                                                    intent_status_counts);
          },
          [&](const charter::schema::upsert_attestation_t& operation) {
            return execute_upsert_attestation_operation(storage, encoder,
                                                        operation, now_ms);
          },
          [&](const charter::schema::revoke_attestation_t& operation) {
            return execute_revoke_attestation_operation(storage, encoder,
                                                        operation);
          },
          [&](const charter::schema::propose_destination_update_t& operation) {
            return execute_propose_destination_update_operation(
                storage, encoder, operation, tx.signer, now_ms);
          },
          [&](const charter::schema::approve_destination_update_t& operation) {
            return execute_approve_destination_update_operation(
                storage, encoder, operation, tx.signer, now_ms);
          },
          [&](const charter::schema::apply_destination_update_t& operation) {
            return execute_apply_destination_update_operation(
                storage, encoder, operation, now_ms);
          },
          [&](const charter::schema::upsert_role_assignment_t& operation) {
            return execute_upsert_role_assignment_operation(
                storage, encoder, operation, tx.signer, now_ms,
                current_block_height, security_event_total,
                security_severity_counts);
          },
          [&](const charter::schema::upsert_signer_quarantine_t& operation) {
            return execute_upsert_signer_quarantine_operation(
                storage, encoder, operation, tx.signer, now_ms,
                current_block_height, security_event_total,
                security_severity_counts);
          },
          [&](const charter::schema::set_degraded_mode_t& operation) {
            return execute_set_degraded_mode_operation(
                storage, encoder, operation, tx.signer, now_ms,
                current_block_height, security_event_total,
                security_severity_counts);
          }},
      tx.payload);
}

std::pair<std::optional<charter::schema::hash32_t>,
          std::optional<charter::schema::hash32_t>>
scope_ids_for_payload(const charter::schema::transaction_payload_t& payload) {
  auto workspace_id = std::optional<charter::schema::hash32_t>{};
  auto vault_id = std::optional<charter::schema::hash32_t>{};
  auto payload_scope = scope_from_payload(payload);
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
  return std::pair{workspace_id, vault_id};
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

template <typename Encoder>
charter::schema::bytes_t make_signing_bytes(
    Encoder& encoder,
    const charter::schema::transaction_t& tx) {
  // The signature envelope excludes the signature field itself and signs a
  // canonical tuple of immutable transaction fields.
  return encoder.encode(
      std::tuple{tx.version, tx.chain_id, tx.nonce, tx.signer, tx.payload});
}

template <typename Encoder>
charter::schema::hash32_t fold_app_hash(Encoder& encoder,
                                        const charter::schema::hash32_t& seed,
                                        const charter::schema::bytes_t& tx,
                                        uint64_t height,
                                        uint64_t index) {
  auto material = charter::schema::bytes_t{};
  material.reserve(seed.size() + tx.size() + 32);
  material.insert(std::end(material), std::begin(seed), std::end(seed));
  material.insert(std::end(material), std::begin(tx), std::end(tx));

  auto encoded_suffix = encoder.encode(std::tuple{height, index});
  material.insert(std::end(material), std::begin(encoded_suffix),
                  std::end(encoded_suffix));
  return charter::blake3::hash(
      charter::schema::bytes_view_t{material.data(), material.size()});
}

template <typename Encoder>
std::optional<charter::schema::transaction_t> decode_transaction(
    Encoder& encoder,
    const charter::schema::bytes_view_t& raw_tx,
    std::string& error) {
  if (raw_tx.empty()) {
    error = "empty transaction";
    return std::nullopt;
  }
  auto tx = encoder.template try_decode<charter::schema::transaction_t>(raw_tx);
  if (!tx) {
    error = "failed to decode transaction";
    return std::nullopt;
  }
  return tx;
}

charter::schema::snapshot_descriptor_t make_snapshot_descriptor(
    uint64_t height,
    const charter::schema::bytes_t& chunk) {
  auto snapshot = charter::schema::snapshot_descriptor_t{};
  snapshot.height = height;
  snapshot.format = 1;
  snapshot.chunks = 1;
  snapshot.hash = charter::blake3::hash(
      charter::schema::bytes_view_t{chunk.data(), chunk.size()});
  snapshot.metadata =
      charter::schema::make_bytes(std::string_view{"charter-snapshot-v1"});
  return snapshot;
}

bool key_starts_with_prefix(const charter::schema::bytes_t& key,
                            const charter::schema::bytes_t& prefix) {
  return key.size() >= prefix.size() &&
         std::equal(std::begin(prefix), std::end(prefix), std::begin(key));
}

template <typename Encoder>
std::vector<charter::schema::bytes_t> make_state_prefixes(Encoder& encoder) {
  auto prefixes = std::vector<charter::schema::bytes_t>{};
  for (const auto& keyspace : kEngineKeyspaces) {
    if (keyspace.starts_with(kStatePrefix)) {
      prefixes.emplace_back(make_prefix_key(encoder, keyspace));
    }
  }
  return prefixes;
}

std::vector<charter::storage::key_value_entry_t> list_state_entries(
    const charter::storage::storage<charter::storage::rocksdb_storage_tag>&
        storage,
    const std::vector<charter::schema::bytes_t>& state_prefixes) {
  auto state_entries = std::vector<charter::storage::key_value_entry_t>{};
  for (const auto& prefix : state_prefixes) {
    auto rows = storage.list_by_prefix(
        charter::schema::bytes_view_t{prefix.data(), prefix.size()});
    state_entries.insert(std::end(state_entries), std::begin(rows),
                         std::end(rows));
  }
  return state_entries;
}

void replace_state_entries(
    const charter::storage::storage<charter::storage::rocksdb_storage_tag>&
        storage,
    const std::vector<charter::schema::bytes_t>& state_prefixes,
    const std::vector<charter::storage::key_value_entry_t>& state_entries) {
  for (const auto& prefix : state_prefixes) {
    auto entries_for_prefix =
        std::vector<charter::storage::key_value_entry_t>{};
    for (const auto& entry : state_entries) {
      if (key_starts_with_prefix(entry.first, prefix)) {
        entries_for_prefix.emplace_back(entry);
      }
    }
    storage.replace_by_prefix(
        charter::schema::bytes_view_t{prefix.data(), prefix.size()},
        entries_for_prefix);
  }
}

template <typename Encoder>
charter::schema::bytes_t make_state_snapshot_chunk(
    Encoder& encoder,
    const charter::storage::storage<charter::storage::rocksdb_storage_tag>&
        storage) {
  auto state_prefixes = make_state_prefixes(encoder);
  auto state_entries = list_state_entries(storage, state_prefixes);
  auto chunk = encoder.encode(std::tuple{uint16_t{1}, state_entries});
  spdlog::debug("Built snapshot chunk with {} state records",
                state_entries.size());
  return chunk;
}

template <typename Encoder>
bool restore_state_snapshot_chunk(
    Encoder& encoder,
    const charter::storage::storage<charter::storage::rocksdb_storage_tag>&
        storage,
    const charter::schema::bytes_view_t& chunk,
    std::string& error) {
  auto decoded = encoder.template try_decode<
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
  auto state_prefixes = make_state_prefixes(encoder);
  replace_state_entries(storage, state_prefixes, std::get<1>(decoded.value()));
  return true;
}

}  // namespace

namespace charter::execution {

engine::engine(
    charter::schema::encoding::encoder<
        charter::schema::encoding::scale_encoder_tag>& encoder,
    charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
    uint64_t snapshot_interval,
    bool require_strict_crypto)
    : encoder_{encoder},
      storage_{storage},
      chain_id_{make_chain_id()},
      require_strict_crypto_{require_strict_crypto},
      snapshot_interval_{snapshot_interval} {
  spdlog::info(
      "Initializing execution engine:  snapshot_interval={} "
      "strict_crypto={} chain_id={}",
      snapshot_interval_, require_strict_crypto,
      to_hex(
          charter::schema::bytes_view_t{chain_id_.data(), chain_id_.size()}));
  load_persisted_state();

  if (last_committed_state_root_.empty()) {
    last_committed_state_root_ = make_zero_hash();
    pending_state_root_ = last_committed_state_root_;
    storage_.save_committed_state(
        encoder_, charter::storage::committed_state{
                      .height = last_committed_height_,
                      .state_root = last_committed_state_root_});
  }
  if (snapshot_interval_ == 0) {
    spdlog::warn("Snapshot interval is 0; snapshots disabled");
  }
  auto crypto_available = charter::crypto::available();
  if (require_strict_crypto_) {
    if (!crypto_available) {
      charter::common::critical(
          "OpenSSL backend unavailable for strict signature verification");
    }
    signature_verifier_ = charter::crypto::verify_signature;
    signature_verifier_overridden_ = false;
  } else {
    if (crypto_available) {
      spdlog::warn(
          "Strict signature verification disabled by configuration; "
          "signature checks are bypassed");
    } else {
      spdlog::warn(
          "OpenSSL backend unavailable for full signature verification; "
          "signature checks are bypassed");
    }
    signature_verifier_ = {};
    signature_verifier_overridden_ = false;
  }
  spdlog::info("Execution engine ready at height {} with {} snapshot(s)",
               last_committed_height_, snapshots_.size());
}

transaction_result_t engine::check_transaction(
    const charter::schema::bytes_view_t& raw_tx) {
  // CheckTx performs stateless+stateful admission checks but never mutates
  // ledger state.
  auto lock = std::scoped_lock{mutex_};
  auto decode_error = std::string{};
  auto maybe_tx = decode_transaction(
      encoder_, charter::schema::bytes_view_t{raw_tx.data(), raw_tx.size()},
      decode_error);
  if (!maybe_tx) {
    return make_error_transaction_result(
        charter::schema::transaction_error_code::invalid_transaction,
        "invalid transaction", decode_error, std::string{kCheckTxCodespace});
  }
  auto result =
      validate_transaction(*maybe_tx, kCheckTxCodespace, std::nullopt);
  if (result.code != 0) {
    return result;
  }
  result.gas_wanted = 1000;
  return result;
}

transaction_result_t engine::process_proposal_transaction(
    const charter::schema::bytes_view_t& raw_tx) {
  // PrepareProposal reuses the same validation pipeline as CheckTx so proposer
  // filtering logic does not diverge from validator logic.
  auto lock = std::scoped_lock{mutex_};
  auto decode_error = std::string{};
  auto maybe_tx = decode_transaction(encoder_, raw_tx, decode_error);
  if (!maybe_tx) {
    return make_error_transaction_result(
        charter::schema::transaction_error_code::invalid_transaction,
        "invalid transaction", decode_error, std::string{kProposalCodespace});
  }
  auto result =
      validate_transaction(*maybe_tx, kProposalCodespace, std::nullopt);
  if (result.code == 0) {
    result.gas_wanted = 1000;
  }
  return result;
}

transaction_result_t engine::execute_operation(
    const charter::schema::transaction_t& tx) {
  // Execute the payload and emit security telemetry for denied operations.
  auto result = execute_payload_operation(
      storage_, encoder_, tx, current_block_time_ms_, current_block_height_,
      metrics_intent_status_counts_, metrics_security_event_total_,
      metrics_security_severity_counts_);
  auto [workspace_id, vault_id] = scope_ids_for_payload(tx.payload);

  if (result.code != 0) {
    append_security_event(storage_, encoder_,
                          event_type_for_transaction_error(result.code, false),
                          charter::schema::security_event_severity_t::error,
                          result.code, result.log, tx.signer, workspace_id,
                          vault_id, current_block_time_ms_,
                          current_block_height_, &metrics_security_event_total_,
                          &metrics_security_severity_counts_);
  }

  if (result.code == 0) {
    result.gas_wanted = 1000;
    result.gas_used = 750;
  }
  return result;
}

transaction_result_t engine::validate_transaction(
    const charter::schema::transaction_t& tx,
    std::string_view codespace,
    std::optional<uint64_t> expected_nonce) {
  // Validation order matters:
  // 1) safety gates (degraded mode / quarantine)
  // 2) authorization gates
  // 3) envelope + signature checks
  // 4) nonce sequencing
  auto degraded_mode = current_degraded_mode(storage_, encoder_);
  if (degraded_mode != charter::schema::degraded_mode_t::normal &&
      !std::holds_alternative<charter::schema::set_degraded_mode_t>(
          tx.payload)) {
    return make_error_transaction_result(
        charter::schema::transaction_error_code::degraded_mode_active,
        "degraded mode active", "only degraded mode updates are allowed",
        std::string{codespace});
  }
  if (signer_quarantined(storage_, encoder_, tx.signer,
                         current_block_time_ms_)) {
    return make_error_transaction_result(
        charter::schema::transaction_error_code::signer_quarantined,
        "signer quarantined", "signer is blocked by quarantine policy",
        std::string{codespace});
  }
  if (!signer_authorized_for_payload(storage_, encoder_, tx.payload, tx.signer,
                                     current_block_time_ms_)) {
    return make_error_transaction_result(
        charter::schema::transaction_error_code::authorization_denied,
        "authorization denied", "signer lacks required role for operation",
        std::string{codespace});
  }

  if (tx.version != 1) {
    return make_error_transaction_result(
        charter::schema::transaction_error_code::
            unsupported_transaction_version,
        "unsupported transaction version", "expected version 1",
        std::string{codespace});
  }
  if (tx.chain_id != chain_id_) {
    return make_error_transaction_result(
        charter::schema::transaction_error_code::invalid_chain_id,
        "invalid chain id", "transaction chain_id does not match app chain_id",
        std::string{codespace});
  }
  if (!signer_signature_compatible(tx.signer, tx.signature)) {
    return make_error_transaction_result(
        charter::schema::transaction_error_code::invalid_signature_type,
        "invalid signature type",
        "signer_id and signature variant are incompatible",
        std::string{codespace});
  }
  auto signing_bytes = make_signing_bytes(encoder_, tx);
  // In non-strict mode, signatures are always bypassed for PoC/demo workflows.
  // Runtime verifier overrides are only honored when strict crypto is enabled.
  auto should_verify_signature = require_strict_crypto_;
  spdlog::debug(
      "signature gate: strict={} overridden={} has_verifier={} codespace={}",
      require_strict_crypto_, signature_verifier_overridden_,
      static_cast<bool>(signature_verifier_), codespace);
  if (should_verify_signature && !signature_verifier_) {
    return make_error_transaction_result(
        charter::schema::transaction_error_code::signature_verification_failed,
        "signature verification failed",
        "signature verifier is not configured in verification-required mode",
        std::string{codespace});
  }
  if (should_verify_signature &&
      !signature_verifier_(charter::schema::bytes_view_t{signing_bytes.data(),
                                                         signing_bytes.size()},
                           tx.signer, tx.signature)) {
    return make_error_transaction_result(
        charter::schema::transaction_error_code::signature_verification_failed,
        "signature verification failed",
        "signature verifier rejected transaction signature",
        std::string{codespace});
  }

  auto nonce_to_match = uint64_t{};
  if (expected_nonce.has_value()) {
    // During FinalizeBlock we carry a per-block nonce cursor so multiple
    // transactions from the same signer validate in-order within the block.
    nonce_to_match = expected_nonce.value();
  } else {
    auto nonce_key = make_nonce_key(encoder_, tx.signer);
    auto stored_nonce = storage_.get<uint64_t>(
        encoder_,
        charter::schema::bytes_view_t{nonce_key.data(), nonce_key.size()});
    nonce_to_match = stored_nonce.value_or(0) + 1;
  }

  if (tx.nonce != nonce_to_match) {
    return make_error_transaction_result(
        charter::schema::transaction_error_code::invalid_nonce, "invalid nonce",
        "expected nonce " + std::to_string(nonce_to_match),
        std::string{codespace});
  }

  return transaction_result_t{};
}

block_result_t engine::finalize_block(
    uint64_t height,
    const std::vector<charter::schema::bytes_t>& txs) {
  auto lock = std::scoped_lock{mutex_};
  auto result = block_result_t{};
  result.tx_results.reserve(txs.size());
  current_block_time_ms_ = height * 1000;
  current_block_height_ = height;

  // Rolling state_root is updated only for successfully executed transactions.
  auto rolling_hash = last_committed_state_root_;
  // Tracks next expected nonce per signer while iterating transactions in the
  // candidate block.
  auto expected_nonces = std::map<charter::schema::bytes_t, uint64_t>{};
  for (size_t i = 0; i < txs.size(); ++i) {
    auto decode_error = std::string{};
    auto maybe_tx = decode_transaction(
        encoder_, charter::schema::bytes_view_t{txs[i].data(), txs[i].size()},
        decode_error);
    if (!maybe_tx) {
      auto tx_result = make_error_transaction_result(
          charter::schema::transaction_error_code::invalid_transaction,
          "invalid transaction", decode_error, "charter.finalize");
      auto history_key =
          make_history_key(encoder_, height, static_cast<uint32_t>(i));
      storage_.put(
          encoder_,
          charter::schema::bytes_view_t{history_key.data(), history_key.size()},
          std::tuple{tx_result.code, txs[i]});
      record_history_code_counters(tx_result.code, metrics_transaction_total_,
                                   metrics_transaction_failed_,
                                   metrics_transaction_code_counts_);
      append_security_event(
          storage_, encoder_,
          event_type_for_transaction_error(tx_result.code, true),
          charter::schema::security_event_severity_t::error, tx_result.code,
          tx_result.log, std::nullopt, std::nullopt, std::nullopt,
          current_block_time_ms_, current_block_height_,
          &metrics_security_event_total_, &metrics_security_severity_counts_);
      append_transaction_result_event(encoder_, tx_result, height,
                                      static_cast<uint32_t>(i), std::nullopt);
      result.tx_results.emplace_back(std::move(tx_result));
      continue;
    }
    auto signer_key = make_signer_cache_key(encoder_, maybe_tx->signer);
    auto expected_nonce = std::optional<uint64_t>{};
    if (auto it = expected_nonces.find(signer_key);
        it != std::end(expected_nonces)) {
      expected_nonce = it->second;
    }
    auto validation =
        validate_transaction(*maybe_tx, "charter.finalize", expected_nonce);
    if (validation.code != 0) {
      auto history_key =
          make_history_key(encoder_, height, static_cast<uint32_t>(i));
      storage_.put(
          encoder_,
          charter::schema::bytes_view_t{history_key.data(), history_key.size()},
          std::tuple{validation.code, txs[i]});
      record_history_code_counters(validation.code, metrics_transaction_total_,
                                   metrics_transaction_failed_,
                                   metrics_transaction_code_counts_);
      append_security_event(
          storage_, encoder_,
          event_type_for_transaction_error(validation.code, true),
          charter::schema::security_event_severity_t::error, validation.code,
          validation.log, maybe_tx->signer, std::nullopt, std::nullopt,
          current_block_time_ms_, current_block_height_,
          &metrics_security_event_total_, &metrics_security_severity_counts_);
      append_transaction_result_event(encoder_, validation, height,
                                      static_cast<uint32_t>(i), maybe_tx);
      result.tx_results.emplace_back(std::move(validation));
      continue;
    }

    auto tx_result = execute_operation(*maybe_tx);
    auto history_key =
        make_history_key(encoder_, height, static_cast<uint32_t>(i));
    storage_.put(
        encoder_,
        charter::schema::bytes_view_t{history_key.data(), history_key.size()},
        std::tuple{tx_result.code, txs[i]});
    record_history_code_counters(tx_result.code, metrics_transaction_total_,
                                 metrics_transaction_failed_,
                                 metrics_transaction_code_counts_);
    append_transaction_result_event(encoder_, tx_result, height,
                                    static_cast<uint32_t>(i), maybe_tx);
    result.tx_results.emplace_back(std::move(tx_result));
    if (tx_result.code == 0) {
      // Persist signer nonce only on successful execution.
      auto nonce_key = make_nonce_key(encoder_, maybe_tx->signer);
      storage_.put(
          encoder_,
          charter::schema::bytes_view_t{nonce_key.data(), nonce_key.size()},
          maybe_tx->nonce);
      expected_nonces[signer_key] = maybe_tx->nonce + 1;
      rolling_hash = fold_app_hash(encoder_, rolling_hash, txs[i], height, i);
    }
  }

  pending_height_ = static_cast<int64_t>(height);
  pending_state_root_ = rolling_hash;
  result.state_root = rolling_hash;
  return result;
}

commit_result_t engine::commit() {
  auto lock = std::scoped_lock{mutex_};
  if (pending_height_ > 0) {
    last_committed_height_ = pending_height_;
    last_committed_state_root_ = pending_state_root_;
    pending_height_ = 0;
  }

  create_snapshot_if_due(last_committed_height_);
  storage_.save_committed_state(encoder_,
                                charter::storage::committed_state{
                                    .height = last_committed_height_,
                                    .state_root = last_committed_state_root_});

  auto result = commit_result_t{};
  result.retain_height = 0;
  result.committed_height = last_committed_height_;
  result.state_root = last_committed_state_root_;
  return result;
}

app_info_t engine::info() const {
  auto lock = std::scoped_lock{mutex_};
  auto result = app_info_t{};
  result.last_block_height = last_committed_height_;
  result.last_block_state_root = last_committed_state_root_;
  return result;
}

query_result_t engine::query(std::string_view path,
                             const charter::schema::bytes_view_t& data) {
  auto lock = std::scoped_lock{mutex_};
  auto request = query_request_context{
      .storage = storage_,
      .encoder = encoder_,
      .last_committed_height = last_committed_height_,
      .last_committed_state_root = last_committed_state_root_,
      .chain_id = chain_id_,
      .metrics_transaction_total = metrics_transaction_total_,
      .metrics_transaction_failed = metrics_transaction_failed_,
      .metrics_security_event_total = metrics_security_event_total_,
      .metrics_snapshots_total = metrics_snapshots_total_,
      .metrics_transaction_code_counts = metrics_transaction_code_counts_,
      .metrics_security_severity_counts = metrics_security_severity_counts_,
      .metrics_intent_status_counts = metrics_intent_status_counts_,
      .data = data};

  // Route table keeps query behavior deterministic and easy to audit.
  for (const auto& route : kQueryRoutes) {
    if (path == route.path) {
      return route.handler(request);
    }
  }

  return query_unsupported_path(request);
}

std::vector<history_entry_t> engine::history(uint64_t from_height,
                                             uint64_t to_height) const {
  auto lock = std::scoped_lock{mutex_};
  auto output = std::vector<history_entry_t>{};
  for_each_history_row(
      storage_, encoder_,
      [&](uint64_t height, uint32_t index, uint32_t code,
          const charter::schema::bytes_t& tx_bytes) {
        if (height < from_height || height > to_height) {
          return;
        }
        output.emplace_back(history_entry_t{
            .height = height, .index = index, .code = code, .tx = tx_bytes});
      });
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
  auto state_prefixes = make_state_prefixes(encoder_);
  auto history_prefix = make_prefix_key(encoder_, kHistoryPrefix);
  auto snapshot_prefix = charter::schema::make_bytes(kSnapshotPrefix);
  auto state = list_state_entries(storage_, state_prefixes);
  auto history_rows = storage_.list_by_prefix(charter::schema::bytes_view_t{
      history_prefix.data(), history_prefix.size()});
  auto snapshots = storage_.list_by_prefix(charter::schema::bytes_view_t{
      snapshot_prefix.data(), snapshot_prefix.size()});
  auto committed = storage_.load_committed_state(encoder_);

  return encoder_.encode(std::tuple{uint16_t{1}, committed, state, history_rows,
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
  auto decoded = encoder_.try_decode<
      std::tuple<uint16_t, std::optional<charter::storage::committed_state>,
                 std::vector<charter::storage::key_value_entry_t>,
                 std::vector<charter::storage::key_value_entry_t>,
                 std::vector<charter::storage::key_value_entry_t>,
                 charter::schema::hash32_t>>(backup);
  if (!decoded) {
    error = "failed to decode backup bundle";
    append_security_event(
        storage_, encoder_,
        charter::schema::security_event_type_t::backup_import_failed,
        charter::schema::security_event_severity_t::error, 1, error,
        std::nullopt, std::nullopt, std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_),
        &metrics_security_event_total_, &metrics_security_severity_counts_);
    return false;
  }
  if (std::get<0>(decoded.value()) != 1) {
    error = "unsupported backup bundle version";
    append_security_event(
        storage_, encoder_,
        charter::schema::security_event_type_t::backup_import_failed,
        charter::schema::security_event_severity_t::error, 1, error,
        std::nullopt, std::nullopt, std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_),
        &metrics_security_event_total_, &metrics_security_severity_counts_);
    return false;
  }
  if (std::get<5>(decoded.value()) != chain_id_) {
    error = "backup chain_id mismatch";
    append_security_event(
        storage_, encoder_,
        charter::schema::security_event_type_t::backup_import_failed,
        charter::schema::security_event_severity_t::error, 1, error,
        std::nullopt, std::nullopt, std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_),
        &metrics_security_event_total_, &metrics_security_severity_counts_);
    return false;
  }

  auto state_prefixes = make_state_prefixes(encoder_);
  auto history_prefix = make_prefix_key(encoder_, kHistoryPrefix);
  auto snapshot_prefix = charter::schema::make_bytes(kSnapshotPrefix);

  replace_state_entries(storage_, state_prefixes, std::get<2>(decoded.value()));
  storage_.replace_by_prefix(
      charter::schema::bytes_view_t{history_prefix.data(),
                                    history_prefix.size()},
      std::get<3>(decoded.value()));
  storage_.replace_by_prefix(
      charter::schema::bytes_view_t{snapshot_prefix.data(),
                                    snapshot_prefix.size()},
      std::get<4>(decoded.value()));

  if (std::get<1>(decoded.value()).has_value()) {
    storage_.save_committed_state(encoder_,
                                  std::get<1>(decoded.value()).value());
  }
  load_persisted_state();
  return true;
}

replay_result_t engine::replay_history() {
  auto lock = std::scoped_lock{mutex_};
  auto result = replay_result_t{};
  auto expected_committed = storage_.load_committed_state(encoder_);
  auto state_prefixes = make_state_prefixes(encoder_);

  auto history_prefix = make_prefix_key(encoder_, kHistoryPrefix);
  auto history_rows = storage_.list_by_prefix(charter::schema::bytes_view_t{
      history_prefix.data(), history_prefix.size()});
  replace_state_entries(storage_, state_prefixes, {});

  auto expected_nonces = std::map<charter::schema::bytes_t, uint64_t>{};
  auto rolling_hash = charter::schema::make_zero_hash();
  auto max_height = uint64_t{};
  for (const auto& [key, value] : history_rows) {
    auto parsed = parse_history_key(
        encoder_, charter::schema::bytes_view_t{key.data(), key.size()});
    if (!parsed) {
      continue;
    }
    auto [height, index] = *parsed;
    current_block_time_ms_ = height * 1000;
    auto decoded =
        encoder_.try_decode<std::tuple<uint32_t, charter::schema::bytes_t>>(
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
        encoder_, charter::schema::bytes_view_t{raw_tx.data(), raw_tx.size()},
        decode_error);
    if (!maybe_tx) {
      if (stored_code == 1) {
        continue;
      }
      result.error = "failed decoding history tx during replay";
      spdlog::warn("History replay failed: {}", result.error);
      return result;
    }
    auto signer_key = make_signer_cache_key(encoder_, maybe_tx->signer);
    auto expected_nonce = std::optional<uint64_t>{};
    if (auto it = expected_nonces.find(signer_key);
        it != std::end(expected_nonces)) {
      expected_nonce = it->second;
    }
    auto validation =
        validate_transaction(*maybe_tx, "charter.replay", expected_nonce);
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
    auto nonce_key = make_nonce_key(encoder_, maybe_tx->signer);
    storage_.put(
        encoder_,
        charter::schema::bytes_view_t{nonce_key.data(), nonce_key.size()},
        maybe_tx->nonce);
    expected_nonces[signer_key] = maybe_tx->nonce + 1;
    rolling_hash = fold_app_hash(encoder_, rolling_hash, raw_tx, height, index);
    result.applied_count += 1;
  }

  last_committed_height_ = static_cast<int64_t>(max_height);
  last_committed_state_root_ = rolling_hash;
  pending_state_root_ = rolling_hash;
  storage_.save_committed_state(encoder_,
                                charter::storage::committed_state{
                                    .height = last_committed_height_,
                                    .state_root = last_committed_state_root_});
  load_persisted_state();

  if (expected_committed.has_value() &&
      (expected_committed->height != last_committed_height_ ||
       expected_committed->state_root != last_committed_state_root_)) {
    spdlog::warn(
        "Replay checkpoint mismatch (stored height={}, replayed height={})",
        expected_committed->height, last_committed_height_);
    result.error = "replayed state differs from prior committed checkpoint";
    append_security_event(
        storage_, encoder_,
        charter::schema::security_event_type_t::replay_checkpoint_mismatch,
        charter::schema::security_event_severity_t::warning, 0, result.error,
        std::nullopt, std::nullopt, std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_),
        &metrics_security_event_total_, &metrics_security_severity_counts_);
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
  if (!require_strict_crypto_) {
    spdlog::warn(
        "set_signature_verifier ignored because strict crypto is disabled");
    signature_verifier_ = {};
    signature_verifier_overridden_ = false;
    return;
  }
  spdlog::warn(
      "set_signature_verifier called at runtime (strict={} "
      "current_overridden={} "
      "new_has_verifier={})",
      require_strict_crypto_, signature_verifier_overridden_,
      static_cast<bool>(verifier));
  signature_verifier_ = std::move(verifier);
  signature_verifier_overridden_ = true;
}

std::vector<snapshot_descriptor_t> engine::list_snapshots() const {
  auto lock = std::scoped_lock{mutex_};
  return snapshots_;
}

std::optional<charter::schema::bytes_t> engine::load_snapshot_chunk(
    uint64_t height,
    uint32_t format,
    uint32_t chunk) const {
  auto lock = std::scoped_lock{mutex_};
  auto loaded = storage_.load_snapshot_chunk(encoder_, height, format, chunk);
  if (!loaded) {
    spdlog::warn("Snapshot chunk not found: h={}, f={}, c={}", height, format,
                 chunk);
  }
  return loaded;
}

offer_snapshot_result engine::offer_snapshot(
    const snapshot_descriptor_t& offered,
    const charter::schema::hash32_t& trusted_state_root) {
  auto lock = std::scoped_lock{mutex_};
  if (offered.format != 1) {
    spdlog::warn("Rejecting snapshot offer with unsupported format {}",
                 offered.format);
    append_security_event(
        storage_, encoder_,
        charter::schema::security_event_type_t::snapshot_rejected,
        charter::schema::security_event_severity_t::warning, 0,
        "snapshot format rejected", std::nullopt, std::nullopt, std::nullopt,
        current_block_time_ms_, static_cast<uint64_t>(last_committed_height_),
        &metrics_security_event_total_, &metrics_security_severity_counts_);
    return offer_snapshot_result::reject_format;
  }
  if (offered.chunks != 1) {
    spdlog::warn("Rejecting snapshot offer with unsupported chunk count {}",
                 offered.chunks);
    append_security_event(
        storage_, encoder_,
        charter::schema::security_event_type_t::snapshot_rejected,
        charter::schema::security_event_severity_t::warning, 0,
        "snapshot chunk count rejected", std::nullopt, std::nullopt,
        std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_),
        &metrics_security_event_total_, &metrics_security_severity_counts_);
    return offer_snapshot_result::reject;
  }
  if (!trusted_state_root.empty() && trusted_state_root != offered.hash) {
    spdlog::warn("Rejecting snapshot offer at height {} due to hash mismatch",
                 offered.height);
    append_security_event(
        storage_, encoder_,
        charter::schema::security_event_type_t::snapshot_rejected,
        charter::schema::security_event_severity_t::warning, 0,
        "snapshot trusted hash rejected", std::nullopt, std::nullopt,
        std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_),
        &metrics_security_event_total_, &metrics_security_severity_counts_);
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
    append_security_event(
        storage_, encoder_,
        charter::schema::security_event_type_t::snapshot_rejected,
        charter::schema::security_event_severity_t::warning, 0,
        "snapshot chunk hash mismatch", std::nullopt, std::nullopt,
        std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_),
        &metrics_security_event_total_, &metrics_security_severity_counts_);
    return apply_snapshot_chunk_result::reject_snapshot;
  }
  auto restore_error = std::string{};
  if (!restore_state_snapshot_chunk(encoder_, storage_, chunk, restore_error)) {
    spdlog::error("Failed to restore snapshot chunk: {}", restore_error);
    append_security_event(
        storage_, encoder_,
        charter::schema::security_event_type_t::snapshot_rejected,
        charter::schema::security_event_severity_t::error, 0, restore_error,
        std::nullopt, std::nullopt, std::nullopt, current_block_time_ms_,
        static_cast<uint64_t>(last_committed_height_),
        &metrics_security_event_total_, &metrics_security_severity_counts_);
    return apply_snapshot_chunk_result::reject_snapshot;
  }

  last_committed_height_ =
      static_cast<int64_t>(pending_snapshot_offer_->height);
  last_committed_state_root_ = pending_snapshot_offer_->hash;
  pending_state_root_ = last_committed_state_root_;
  storage_.save_committed_state(encoder_,
                                charter::storage::committed_state{
                                    .height = last_committed_height_,
                                    .state_root = last_committed_state_root_});
  auto existing =
      std::ranges::find_if(snapshots_, [&](const snapshot_descriptor_t& value) {
        return value.height == pending_snapshot_offer_->height &&
               value.format == pending_snapshot_offer_->format;
      });
  if (existing == std::end(snapshots_)) {
    snapshots_.emplace_back(*pending_snapshot_offer_);
  } else {
    *existing = *pending_snapshot_offer_;
  }
  rebuild_observability_counters(
      storage_, encoder_, snapshots_, metrics_transaction_total_,
      metrics_transaction_failed_, metrics_transaction_code_counts_,
      metrics_security_event_total_, metrics_security_severity_counts_,
      metrics_intent_status_counts_, metrics_snapshots_total_);
  pending_snapshot_offer_.reset();
  spdlog::info("Applied snapshot chunk {}", index);
  append_security_event(
      storage_, encoder_,
      charter::schema::security_event_type_t::snapshot_applied,
      charter::schema::security_event_severity_t::info, 0, "snapshot applied",
      std::nullopt, std::nullopt, std::nullopt, current_block_time_ms_,
      static_cast<uint64_t>(last_committed_height_),
      &metrics_security_event_total_, &metrics_security_severity_counts_);
  return apply_snapshot_chunk_result::accept;
}

void engine::create_snapshot_if_due(int64_t height) {
  if (snapshot_interval_ == 0 || height <= 0 ||
      (height % static_cast<int64_t>(snapshot_interval_)) != 0) {
    return;
  }

  auto chunk = make_state_snapshot_chunk(encoder_, storage_);
  auto snapshot =
      make_snapshot_descriptor(static_cast<uint64_t>(height), chunk);
  storage_.save_snapshot(
      encoder_,
      charter::storage::snapshot_descriptor{.height = snapshot.height,
                                            .format = snapshot.format,
                                            .chunks = snapshot.chunks,
                                            .hash = snapshot.hash,
                                            .metadata = snapshot.metadata},
      chunk);

  auto existing =
      std::ranges::find_if(snapshots_, [&](const snapshot_descriptor_t& value) {
        return value.height == snapshot.height &&
               value.format == snapshot.format;
      });
  if (existing == std::end(snapshots_)) {
    snapshots_.emplace_back(snapshot);
  } else {
    *existing = snapshot;
  }
  metrics_snapshots_total_ = static_cast<uint64_t>(snapshots_.size());
  spdlog::info("Created snapshot at height {} format {}", snapshot.height,
               snapshot.format);
}

void engine::load_persisted_state() {
  spdlog::debug("Loading persisted engine state");
  if (auto committed = storage_.load_committed_state(encoder_)) {
    last_committed_height_ = committed->height;
    last_committed_state_root_ = committed->state_root;
    pending_state_root_ = committed->state_root;
  }

  auto stored_snapshots = storage_.list_snapshots(encoder_);
  snapshots_.clear();
  snapshots_.reserve(stored_snapshots.size());
  for (const auto& snapshot : stored_snapshots) {
    snapshots_.emplace_back(
        snapshot_descriptor_t{.height = snapshot.height,
                              .format = snapshot.format,
                              .chunks = snapshot.chunks,
                              .hash = snapshot.hash,
                              .metadata = snapshot.metadata});
  }
  rebuild_observability_counters(
      storage_, encoder_, snapshots_, metrics_transaction_total_,
      metrics_transaction_failed_, metrics_transaction_code_counts_,
      metrics_security_event_total_, metrics_security_severity_counts_,
      metrics_intent_status_counts_, metrics_snapshots_total_);
}

}  // namespace charter::execution

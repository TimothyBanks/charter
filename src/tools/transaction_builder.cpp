#include <boost/program_options.hpp>
#include <charter/blake3/hash.hpp>
#include <charter/common/critical.hpp>
#include <charter/schema/encoding/scale/encoder.hpp>
#include <charter/schema/intent_state.hpp>
#include <charter/schema/transaction.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace {

using encoder_t = charter::schema::encoding::encoder<
    charter::schema::encoding::scale_encoder_tag>;
namespace po = boost::program_options;

charter::schema::hash32_t get_hash32(const po::variables_map& vm,
                                     const std::string& name) {
  if (!vm.contains(name)) {
    charter::common::critical("missing required hash argument");
  }
  return charter::schema::make_hash32(vm[name].as<std::string>());
}

std::optional<charter::schema::hash32_t> get_optional_hash32(
    const po::variables_map& vm,
    const std::string& name) {
  if (!vm.contains(name)) {
    return std::nullopt;
  }
  return charter::schema::make_hash32(vm[name].as<std::string>());
}

std::optional<charter::schema::bytes_t> get_optional_hex_bytes(
    const po::variables_map& vm,
    const std::string& name) {
  if (!vm.contains(name)) {
    return std::nullopt;
  }
  return charter::schema::from_hex(vm[name].as<std::string>());
}

std::optional<charter::schema::timestamp_milliseconds_t> get_optional_timestamp(
    const po::variables_map& vm,
    const std::string& name) {
  if (!vm.contains(name)) {
    return std::nullopt;
  }
  return vm[name].as<uint64_t>();
}

charter::schema::signer_id_t make_named_signer(const po::variables_map& vm,
                                               const std::string& name) {
  return charter::schema::signer_id_t{get_hash32(vm, name)};
}

charter::schema::signature_t make_signature(const po::variables_map& vm) {
  auto kind = vm["signature-kind"].as<std::string>();
  auto bytes =
      vm["signature-hex"].as<std::string>().empty()
          ? charter::schema::bytes_t{}
          : charter::schema::from_hex(vm["signature-hex"].as<std::string>());
  if (kind == "ed25519") {
    auto signature = charter::schema::ed25519_signature_t{};
    if (!bytes.empty()) {
      if (bytes.size() != signature.size()) {
        charter::common::critical("ed25519 signature must be 64 bytes");
      }
      std::copy(std::begin(bytes), std::end(bytes), std::begin(signature));
    }
    return charter::schema::signature_t{signature};
  }
  if (kind == "secp256k1") {
    auto signature = charter::schema::secp256k1_signature_t{};
    if (!bytes.empty()) {
      if (bytes.size() != signature.size()) {
        charter::common::critical("secp256k1 signature must be 65 bytes");
      }
      std::copy(std::begin(bytes), std::end(bytes), std::begin(signature));
    }
    return charter::schema::signature_t{signature};
  }
  charter::common::critical("unsupported signature-kind");
}

charter::schema::claim_type_t parse_claim_type(const std::string& claim) {
  if (claim == "kyb_verified") {
    return charter::schema::claim_type_t{
        charter::schema::claim_type::kyb_verified};
  }
  if (claim == "sanctions_cleared") {
    return charter::schema::claim_type_t{
        charter::schema::claim_type::sanctions_cleared};
  }
  if (claim == "travel_rule_ok") {
    return charter::schema::claim_type_t{
        charter::schema::claim_type::travel_rule_ok};
  }
  if (claim == "risk_approved") {
    return charter::schema::claim_type_t{
        charter::schema::claim_type::risk_approved};
  }
  return charter::schema::claim_type_t{charter::schema::make_hash32(claim)};
}

charter::schema::chain_type_t parse_chain_type(const std::string& chain) {
  auto parsed =
      charter::schema::try_from_string<charter::schema::chain_type>(chain);
  if (parsed.has_value()) {
    return charter::schema::chain_type_t{*parsed};
  }
  return charter::schema::chain_type_t{charter::schema::from_hex(chain)};
}

charter::schema::destination_type_t parse_destination_type(
    const std::string& destination_type) {
  auto parsed =
      charter::schema::try_from_string<charter::schema::destination_type_t>(
          destination_type);
  if (parsed.has_value()) {
    return *parsed;
  }
  charter::common::critical("destination-type must be address|contract");
}

charter::schema::vault_model_t parse_vault_model(const std::string& model) {
  auto parsed =
      charter::schema::try_from_string<charter::schema::vault_model_t>(model);
  if (parsed.has_value()) {
    return *parsed;
  }
  charter::common::critical("vault-model must be segregated|omnibus");
}

charter::schema::asset_kind_t parse_asset_kind(const std::string& kind) {
  auto parsed =
      charter::schema::try_from_string<charter::schema::asset_kind_t>(kind);
  if (parsed.has_value()) {
    return *parsed;
  }
  charter::common::critical(
      "asset-kind must be native|erc20|erc721|erc1115|other");
}

charter::schema::role_id_t parse_role_id(const std::string& role) {
  auto parsed =
      charter::schema::try_from_string<charter::schema::role_id_t>(role);
  if (parsed.has_value()) {
    return *parsed;
  }
  charter::common::critical(
      "role must be "
      "initiator|approver|executor|admin|auditor|guardian|attestor");
}

charter::schema::degraded_mode_t parse_degraded_mode(const std::string& mode) {
  auto parsed =
      charter::schema::try_from_string<charter::schema::degraded_mode_t>(mode);
  if (parsed.has_value()) {
    return *parsed;
  }
  charter::common::critical(
      "degraded-mode must be normal|read_only|emergency_halt");
}

charter::schema::policy_scope_t parse_scope(const po::variables_map& vm) {
  auto scope_type = vm["scope-type"].as<std::string>();
  if (scope_type == "workspace") {
    return charter::schema::policy_scope_t{charter::schema::workspace_scope_t{
        .workspace_id = get_hash32(vm, "workspace-id")}};
  }
  if (scope_type == "vault") {
    return charter::schema::policy_scope_t{
        charter::schema::vault_t{.workspace_id = get_hash32(vm, "workspace-id"),
                                 .vault_id = get_hash32(vm, "vault-id")}};
  }
  charter::common::critical("scope-type must be workspace|vault");
}

charter::schema::signer_id_t get_named_signer_with_fallback(
    const po::variables_map& vm,
    const std::string& primary,
    const std::string& fallback) {
  if (vm.contains(primary)) {
    return make_named_signer(vm, primary);
  }
  return make_named_signer(vm, fallback);
}

std::vector<charter::schema::signer_id_t> make_signer_set(
    const po::variables_map& vm,
    const std::string& list_arg,
    const std::string& fallback_arg) {
  auto signers = std::vector<charter::schema::signer_id_t>{};
  if (vm.contains(list_arg)) {
    for (const auto& value : vm[list_arg].as<std::vector<std::string>>()) {
      signers.push_back(
          charter::schema::signer_id_t{charter::schema::make_hash32(value)});
    }
    return signers;
  }
  signers.push_back(make_named_signer(vm, fallback_arg));
  return signers;
}

std::vector<charter::schema::limit_rule_t> make_limit_rules(
    const po::variables_map& vm) {
  auto limits = std::vector<charter::schema::limit_rule_t>{};
  if (vm.contains("limit-amount")) {
    limits.push_back(charter::schema::limit_rule_t{
        .asset_id = get_hash32(vm, "asset-id"),
        .per_transaction_amount =
            charter::schema::amount_t{vm["limit-amount"].as<uint64_t>()}});
  }
  return limits;
}

std::vector<charter::schema::destination_rule_t> make_destination_rules(
    const po::variables_map& vm) {
  auto destination_rules = std::vector<charter::schema::destination_rule_t>{};
  if (vm["require-whitelisted-destination"].as<bool>()) {
    destination_rules.push_back(
        charter::schema::destination_rule_t{.require_whitelisted = true});
  }
  return destination_rules;
}

std::vector<charter::schema::claim_type_t> make_required_claims(
    const po::variables_map& vm) {
  auto required_claims = std::vector<charter::schema::claim_type_t>{};
  if (vm.contains("required-claim")) {
    for (const auto& claim :
         vm["required-claim"].as<std::vector<std::string>>()) {
      required_claims.push_back(parse_claim_type(claim));
    }
  }
  return required_claims;
}

charter::schema::create_workspace_t make_create_workspace_payload(
    const po::variables_map& vm) {
  return charter::schema::create_workspace_t{
      .workspace_id = get_hash32(vm, "workspace-id"),
      .admin_set = make_signer_set(vm, "admin", "signer"),
      .quorum_size = vm["quorum"].as<uint32_t>(),
      .metadata_ref = get_optional_hash32(vm, "metadata-ref")};
}

charter::schema::create_vault_t make_create_vault_payload(
    const po::variables_map& vm) {
  return charter::schema::create_vault_t{
      .workspace_id = get_hash32(vm, "workspace-id"),
      .vault_id = get_hash32(vm, "vault-id"),
      .model = parse_vault_model(vm["vault-model"].as<std::string>()),
      .label = std::nullopt};
}

charter::schema::upsert_asset_t make_upsert_asset_payload(
    const po::variables_map& vm) {
  auto address_or_contract = charter::schema::from_hex(
      vm["address-or-contract-hex"].as<std::string>());
  if (address_or_contract.empty()) {
    charter::common::critical(
        "upsert_asset requires --address-or-contract-hex");
  }

  auto decimals = vm["asset-decimals"].as<uint32_t>();
  if (decimals > 255u) {
    charter::common::critical("asset-decimals must fit in uint8");
  }

  return charter::schema::upsert_asset_t{
      .asset_id = get_hash32(vm, "asset-id"),
      .chain = parse_chain_type(vm["chain"].as<std::string>()),
      .kind = parse_asset_kind(vm["asset-kind"].as<std::string>()),
      .reference =
          charter::schema::asset_ref_contract_address_t{
              .address = address_or_contract},
      .symbol = get_optional_hex_bytes(vm, "asset-symbol-hex"),
      .name = get_optional_hex_bytes(vm, "asset-name-hex"),
      .decimals = static_cast<uint8_t>(decimals),
      .enabled = vm["asset-enabled"].as<bool>()};
}

charter::schema::disable_asset_t make_disable_asset_payload(
    const po::variables_map& vm) {
  return charter::schema::disable_asset_t{.asset_id =
                                              get_hash32(vm, "asset-id")};
}

charter::schema::upsert_destination_t make_upsert_destination_payload(
    const po::variables_map& vm) {
  return charter::schema::upsert_destination_t{
      .workspace_id = get_hash32(vm, "workspace-id"),
      .destination_id = get_hash32(vm, "destination-id"),
      .type = parse_destination_type(vm["destination-type"].as<std::string>()),
      .chain_type = parse_chain_type(vm["chain"].as<std::string>()),
      .address_or_contract = charter::schema::from_hex(
          vm["address-or-contract-hex"].as<std::string>()),
      .enabled = vm["destination-enabled"].as<bool>(),
      .label = get_optional_hex_bytes(vm, "destination-label")};
}

charter::schema::create_policy_set_t make_create_policy_set_payload(
    const po::variables_map& vm) {
  auto scope = charter::schema::policy_scope_t{
      charter::schema::vault_t{.workspace_id = get_hash32(vm, "workspace-id"),
                               .vault_id = get_hash32(vm, "vault-id")}};

  auto rule = charter::schema::policy_rule_t{
      .operation = charter::schema::operation_type_t::transfer,
      .approvals = {charter::schema::approval_rule_t{
          .approver_role = charter::schema::role_id_t::approver,
          .threshold = vm["threshold"].as<uint32_t>(),
          .require_distinct_from_initiator = false,
          .require_distinct_from_executor = false}},
      .limits = make_limit_rules(vm),
      .time_locks =
          std::vector<charter::schema::time_lock_rule_t>{
              charter::schema::time_lock_rule_t{
                  .operation = charter::schema::operation_type_t::transfer,
                  .delay = vm["timelock-ms"].as<uint64_t>()}},
      .destination_rules = make_destination_rules(vm),
      .required_claims = make_required_claims(vm),
      .velocity_limits = {}};

  return charter::schema::create_policy_set_t{
      .policy_set_id = get_hash32(vm, "policy-set-id"),
      .scope = scope,
      .policy_version =
          static_cast<uint16_t>(vm["policy-version"].as<uint32_t>()),
      .roles = {{charter::schema::role_id_t::approver,
                 make_signer_set(vm, "approver", "signer")}},
      .rules = {rule}};
}

charter::schema::activate_policy_set_t make_activate_policy_set_payload(
    const po::variables_map& vm) {
  return charter::schema::activate_policy_set_t{
      .scope = charter::schema::policy_scope_t{charter::schema::vault_t{
          .workspace_id = get_hash32(vm, "workspace-id"),
          .vault_id = get_hash32(vm, "vault-id")}},
      .policy_set_id = get_hash32(vm, "policy-set-id"),
      .policy_set_version = vm["policy-version"].as<uint32_t>()};
}

charter::schema::propose_intent_t make_propose_intent_payload(
    const po::variables_map& vm) {
  return charter::schema::propose_intent_t{
      .workspace_id = get_hash32(vm, "workspace-id"),
      .vault_id = get_hash32(vm, "vault-id"),
      .intent_id = get_hash32(vm, "intent-id"),
      .action =
          charter::schema::transfer_parameters_t{
              .asset_id = get_hash32(vm, "asset-id"),
              .destination_id = get_hash32(vm, "destination-id"),
              .amount = vm["amount"].as<uint64_t>()},
      .expires_at = get_optional_timestamp(vm, "expires-at")};
}

charter::schema::approve_intent_t make_approve_intent_payload(
    const po::variables_map& vm) {
  return charter::schema::approve_intent_t{
      .workspace_id = get_hash32(vm, "workspace-id"),
      .vault_id = get_hash32(vm, "vault-id"),
      .intent_id = get_hash32(vm, "intent-id")};
}

charter::schema::execute_intent_t make_execute_intent_payload(
    const po::variables_map& vm) {
  return charter::schema::execute_intent_t{
      .workspace_id = get_hash32(vm, "workspace-id"),
      .vault_id = get_hash32(vm, "vault-id"),
      .intent_id = get_hash32(vm, "intent-id")};
}

charter::schema::cancel_intent_t make_cancel_intent_payload(
    const po::variables_map& vm) {
  return charter::schema::cancel_intent_t{
      .workspace_id = get_hash32(vm, "workspace-id"),
      .vault_id = get_hash32(vm, "vault-id"),
      .intent_id = get_hash32(vm, "intent-id")};
}

charter::schema::upsert_attestation_t make_upsert_attestation_payload(
    const po::variables_map& vm) {
  return charter::schema::upsert_attestation_t{
      .workspace_id = get_hash32(vm, "workspace-id"),
      .subject = get_hash32(vm, "subject-id"),
      .claim = parse_claim_type(vm["claim"].as<std::string>()),
      .issuer = make_named_signer(vm, "issuer"),
      .expires_at = vm["attestation-expires-at"].as<uint64_t>(),
      .reference_hash = get_optional_hash32(vm, "reference-hash")};
}

charter::schema::revoke_attestation_t make_revoke_attestation_payload(
    const po::variables_map& vm) {
  return charter::schema::revoke_attestation_t{
      .workspace_id = get_hash32(vm, "workspace-id"),
      .subject = get_hash32(vm, "subject-id"),
      .claim = parse_claim_type(vm["claim"].as<std::string>()),
      .issuer = make_named_signer(vm, "issuer")};
}

charter::schema::propose_destination_update_t
make_propose_destination_update_payload(const po::variables_map& vm) {
  return charter::schema::propose_destination_update_t{
      .workspace_id = get_hash32(vm, "workspace-id"),
      .destination_id = get_hash32(vm, "destination-id"),
      .update_id = get_hash32(vm, "update-id"),
      .type = parse_destination_type(vm["destination-type"].as<std::string>()),
      .chain_type = parse_chain_type(vm["chain"].as<std::string>()),
      .address_or_contract = charter::schema::from_hex(
          vm["address-or-contract-hex"].as<std::string>()),
      .enabled = vm["destination-enabled"].as<bool>(),
      .label = get_optional_hex_bytes(vm, "destination-label"),
      .required_approvals = vm["required-approvals"].as<uint32_t>(),
      .delay_ms = vm["delay-ms"].as<uint64_t>()};
}

charter::schema::approve_destination_update_t
make_approve_destination_update_payload(const po::variables_map& vm) {
  return charter::schema::approve_destination_update_t{
      .workspace_id = get_hash32(vm, "workspace-id"),
      .destination_id = get_hash32(vm, "destination-id"),
      .update_id = get_hash32(vm, "update-id")};
}

charter::schema::apply_destination_update_t
make_apply_destination_update_payload(const po::variables_map& vm) {
  return charter::schema::apply_destination_update_t{
      .workspace_id = get_hash32(vm, "workspace-id"),
      .destination_id = get_hash32(vm, "destination-id"),
      .update_id = get_hash32(vm, "update-id")};
}

charter::schema::upsert_role_assignment_t make_upsert_role_assignment_payload(
    const po::variables_map& vm) {
  return charter::schema::upsert_role_assignment_t{
      .scope = parse_scope(vm),
      .subject = get_named_signer_with_fallback(vm, "subject-signer", "signer"),
      .role = parse_role_id(vm["role"].as<std::string>()),
      .enabled = vm["role-enabled"].as<bool>(),
      .not_before = get_optional_timestamp(vm, "role-not-before"),
      .expires_at = get_optional_timestamp(vm, "role-expires-at"),
      .note = get_optional_hex_bytes(vm, "role-note-hex")};
}

charter::schema::upsert_signer_quarantine_t
make_upsert_signer_quarantine_payload(const po::variables_map& vm) {
  return charter::schema::upsert_signer_quarantine_t{
      .signer = get_named_signer_with_fallback(vm, "target-signer", "signer"),
      .quarantined = vm["quarantined"].as<bool>(),
      .until = get_optional_timestamp(vm, "quarantine-until"),
      .reason = get_optional_hex_bytes(vm, "quarantine-reason-hex")};
}

charter::schema::set_degraded_mode_t make_set_degraded_mode_payload(
    const po::variables_map& vm) {
  return charter::schema::set_degraded_mode_t{
      .mode = parse_degraded_mode(vm["degraded-mode"].as<std::string>()),
      .effective_at = get_optional_timestamp(vm, "effective-at"),
      .reason = get_optional_hex_bytes(vm, "degraded-reason-hex")};
}

charter::schema::transaction_payload_t make_payload(
    const po::variables_map& vm) {
  auto payload = vm["payload"].as<std::string>();
  if (payload == "create_workspace") {
    return make_create_workspace_payload(vm);
  }
  if (payload == "create_vault") {
    return make_create_vault_payload(vm);
  }
  if (payload == "upsert_asset") {
    return make_upsert_asset_payload(vm);
  }
  if (payload == "disable_asset") {
    return make_disable_asset_payload(vm);
  }
  if (payload == "upsert_destination") {
    return make_upsert_destination_payload(vm);
  }
  if (payload == "create_policy_set") {
    return make_create_policy_set_payload(vm);
  }
  if (payload == "activate_policy_set") {
    return make_activate_policy_set_payload(vm);
  }
  if (payload == "propose_intent") {
    return make_propose_intent_payload(vm);
  }
  if (payload == "approve_intent") {
    return make_approve_intent_payload(vm);
  }
  if (payload == "execute_intent") {
    return make_execute_intent_payload(vm);
  }
  if (payload == "cancel_intent") {
    return make_cancel_intent_payload(vm);
  }
  if (payload == "upsert_attestation") {
    return make_upsert_attestation_payload(vm);
  }
  if (payload == "revoke_attestation") {
    return make_revoke_attestation_payload(vm);
  }
  if (payload == "propose_destination_update") {
    return make_propose_destination_update_payload(vm);
  }
  if (payload == "approve_destination_update") {
    return make_approve_destination_update_payload(vm);
  }
  if (payload == "apply_destination_update") {
    return make_apply_destination_update_payload(vm);
  }
  if (payload == "upsert_role_assignment") {
    return make_upsert_role_assignment_payload(vm);
  }
  if (payload == "upsert_signer_quarantine") {
    return make_upsert_signer_quarantine_payload(vm);
  }
  if (payload == "set_degraded_mode") {
    return make_set_degraded_mode_payload(vm);
  }
  charter::common::critical("unsupported payload type");
}

charter::schema::bytes_t make_empty_query_key() {
  return {};
}

charter::schema::bytes_t make_workspace_query_key(const po::variables_map& vm) {
  auto hash = get_hash32(vm, "workspace-id");
  return charter::schema::bytes_t{std::begin(hash), std::end(hash)};
}

charter::schema::bytes_t make_asset_query_key(const po::variables_map& vm) {
  auto hash = get_hash32(vm, "asset-id");
  return charter::schema::bytes_t{std::begin(hash), std::end(hash)};
}

template <typename Encoder>
charter::schema::bytes_t make_vault_query_key(Encoder& encoder,
                                              const po::variables_map& vm) {
  return encoder.encode(
      std::tuple{get_hash32(vm, "workspace-id"), get_hash32(vm, "vault-id")});
}

template <typename Encoder>
charter::schema::bytes_t make_policy_set_query_key(
    Encoder& encoder,
    const po::variables_map& vm) {
  return encoder.encode(std::tuple{get_hash32(vm, "policy-set-id"),
                                   vm["policy-version"].as<uint32_t>()});
}

template <typename Encoder>
charter::schema::bytes_t make_destination_query_key(
    Encoder& encoder,
    const po::variables_map& vm) {
  return encoder.encode(std::tuple{get_hash32(vm, "workspace-id"),
                                   get_hash32(vm, "destination-id")});
}

template <typename Encoder>
charter::schema::bytes_t make_active_policy_query_key(
    Encoder& encoder,
    const po::variables_map& vm) {
  return encoder.encode(charter::schema::policy_scope_t{
      charter::schema::vault_t{.workspace_id = get_hash32(vm, "workspace-id"),
                               .vault_id = get_hash32(vm, "vault-id")}});
}

template <typename Encoder>
charter::schema::bytes_t make_intent_query_key(Encoder& encoder,
                                               const po::variables_map& vm) {
  return encoder.encode(std::tuple{get_hash32(vm, "workspace-id"),
                                   get_hash32(vm, "vault-id"),
                                   get_hash32(vm, "intent-id")});
}

template <typename Encoder>
charter::schema::bytes_t make_approval_query_key(Encoder& encoder,
                                                 const po::variables_map& vm) {
  return encoder.encode(
      std::tuple{get_hash32(vm, "intent-id"), make_named_signer(vm, "signer")});
}

template <typename Encoder>
charter::schema::bytes_t make_attestation_query_key(
    Encoder& encoder,
    const po::variables_map& vm) {
  return encoder.encode(
      std::tuple{get_hash32(vm, "workspace-id"), get_hash32(vm, "subject-id"),
                 parse_claim_type(vm["claim"].as<std::string>()),
                 make_named_signer(vm, "issuer")});
}

template <typename Encoder>
charter::schema::bytes_t make_role_assignment_query_key(
    Encoder& encoder,
    const po::variables_map& vm) {
  return encoder.encode(
      std::tuple{parse_scope(vm),
                 get_named_signer_with_fallback(vm, "subject-signer", "signer"),
                 parse_role_id(vm["role"].as<std::string>())});
}

template <typename Encoder>
charter::schema::bytes_t make_signer_quarantine_query_key(
    Encoder& encoder,
    const po::variables_map& vm) {
  return encoder.encode(
      get_named_signer_with_fallback(vm, "target-signer", "signer"));
}

template <typename Encoder>
charter::schema::bytes_t make_destination_update_query_key(
    Encoder& encoder,
    const po::variables_map& vm) {
  return encoder.encode(std::tuple{get_hash32(vm, "workspace-id"),
                                   get_hash32(vm, "destination-id"),
                                   get_hash32(vm, "update-id")});
}

template <typename Encoder>
charter::schema::bytes_t make_height_range_query_key(
    Encoder& encoder,
    const po::variables_map& vm) {
  return encoder.encode(std::tuple{vm["from-height"].as<uint64_t>(),
                                   vm["to-height"].as<uint64_t>()});
}

template <typename Encoder>
charter::schema::bytes_t make_query_key(Encoder& encoder,
                                        const po::variables_map& vm) {
  auto path = vm["path"].as<std::string>();
  if (path == "/engine/info" || path == "/engine/keyspaces" ||
      path == "/history/export" || path == "/state/degraded_mode") {
    return make_empty_query_key();
  }
  if (path == "/state/workspace") {
    return make_workspace_query_key(vm);
  }
  if (path == "/state/asset") {
    return make_asset_query_key(vm);
  }
  if (path == "/state/vault") {
    return make_vault_query_key(encoder, vm);
  }
  if (path == "/state/policy_set") {
    return make_policy_set_query_key(encoder, vm);
  }
  if (path == "/state/destination") {
    return make_destination_query_key(encoder, vm);
  }
  if (path == "/state/active_policy") {
    return make_active_policy_query_key(encoder, vm);
  }
  if (path == "/state/intent") {
    return make_intent_query_key(encoder, vm);
  }
  if (path == "/state/approval") {
    return make_approval_query_key(encoder, vm);
  }
  if (path == "/state/attestation") {
    return make_attestation_query_key(encoder, vm);
  }
  if (path == "/state/role_assignment") {
    return make_role_assignment_query_key(encoder, vm);
  }
  if (path == "/state/signer_quarantine") {
    return make_signer_quarantine_query_key(encoder, vm);
  }
  if (path == "/state/destination_update") {
    return make_destination_update_query_key(encoder, vm);
  }
  if (path == "/history/range" || path == "/events/range") {
    return make_height_range_query_key(encoder, vm);
  }
  charter::common::critical("unsupported query path");
}

int run_transaction_command(const po::variables_map& vm) {
  if (!vm.contains("payload")) {
    charter::common::critical("transaction mode requires --payload");
  }

  auto transaction =
      charter::schema::transaction_t{.version = 1,
                                     .chain_id = get_hash32(vm, "chain-id"),
                                     .nonce = vm["nonce"].as<uint64_t>(),
                                     .signer = make_named_signer(vm, "signer"),
                                     .payload = make_payload(vm),
                                     .signature = make_signature(vm)};
  auto encoded = encoder_t{}.encode(transaction);
  std::cout << charter::schema::to_base64(encoded) << '\n';
  return 0;
}

int run_query_key_command(const po::variables_map& vm) {
  if (!vm.contains("path")) {
    charter::common::critical("query-key mode requires --path");
  }

  auto encoder = encoder_t{};
  auto key = make_query_key(encoder, vm);
  std::cout << charter::schema::to_base64(key) << '\n';
  return 0;
}

int run_chain_id_command() {
  auto chain_id = charter::blake3::hash(std::string_view{"charter-poc-chain"});
  auto bytes =
      charter::schema::bytes_t{std::begin(chain_id), std::end(chain_id)};
  std::cout << charter::schema::to_hex(charter::schema::make_bytes_view(bytes))
            << '\n';
  return 0;
}

int run_decode_intent_state_command(const po::variables_map& vm) {
  if (!vm.contains("value-base64")) {
    charter::common::critical(
        "decode-intent-state mode requires --value-base64");
  }

  auto encoded =
      charter::schema::from_base64(vm["value-base64"].as<std::string>());
  auto maybe_intent_state =
      encoder_t{}.try_decode<charter::schema::intent_state_t>(
          charter::schema::make_bytes_view(encoded));
  if (!maybe_intent_state.has_value()) {
    charter::common::critical(
        "failed to decode intent_state from --value-base64");
  }
  std::cout << charter::schema::to_string(maybe_intent_state->status) << '\n';
  return 0;
}

void print_help(const po::options_description& options) {
  std::cout
      << "Usage:\n"
      << "  transaction_builder transaction [options]\n"
      << "  transaction_builder query-key [options]\n"
      << "  transaction_builder decode-intent-state --value-base64 <B64>\n"
      << "  transaction_builder chain-id\n\n";
  std::cout << options << '\n';
}

}  // namespace

int main(int argc, const char** argv) {
  auto command = std::string{};
  auto options = po::options_description{"transaction_builder options"};
  options.add_options()("help,h", "show help")(
      "command", po::value<std::string>(&command),
      "transaction|query-key|decode-intent-state|chain-id")(
      "payload", po::value<std::string>(), "transaction payload type")(
      "path", po::value<std::string>(), "abci query path")(
      "value-base64", po::value<std::string>(),
      "base64 SCALE-encoded payload for decode helpers")(
      "chain-id", po::value<std::string>(), "32-byte chain id hex")(
      "nonce", po::value<uint64_t>()->default_value(1), "transaction nonce")(
      "signer", po::value<std::string>(), "named signer hash32 hex")(
      "signature-kind", po::value<std::string>()->default_value("ed25519"),
      "ed25519|secp256k1")("signature-hex",
                           po::value<std::string>()->default_value(""),
                           "signature bytes hex")(
      "workspace-id", po::value<std::string>(), "workspace hash32 hex")(
      "vault-id", po::value<std::string>(), "vault hash32 hex")(
      "policy-set-id", po::value<std::string>(), "policy set hash32 hex")(
      "policy-version", po::value<uint32_t>()->default_value(1),
      "policy version")("intent-id", po::value<std::string>(),
                        "intent hash32 hex")(
      "update-id", po::value<std::string>(), "destination update hash32 hex")(
      "asset-id", po::value<std::string>(), "asset hash32 hex")(
      "asset-kind", po::value<std::string>()->default_value("erc20"),
      "native|erc20|erc721|erc1115|other")(
      "asset-symbol-hex", po::value<std::string>(), "asset symbol bytes hex")(
      "asset-name-hex", po::value<std::string>(), "asset name bytes hex")(
      "asset-decimals", po::value<uint32_t>()->default_value(18),
      "asset decimals (0-255)")(
      "asset-enabled", po::value<bool>()->default_value(true), "asset enabled")(
      "destination-id", po::value<std::string>(), "destination hash32 hex")(
      "amount", po::value<uint64_t>()->default_value(0), "transfer amount")(
      "expires-at", po::value<uint64_t>(), "intent expiry ms")(
      "quorum", po::value<uint32_t>()->default_value(1),
      "workspace quorum size")(
      "admin", po::value<std::vector<std::string>>()->multitoken(),
      "workspace admin signer hash32 values")(
      "metadata-ref", po::value<std::string>(), "workspace metadata hash32")(
      "vault-model", po::value<std::string>()->default_value("segregated"),
      "segregated|omnibus")("destination-type",
                            po::value<std::string>()->default_value("address"),
                            "address|contract")(
      "chain", po::value<std::string>()->default_value("ethereum"),
      "chain name or hex bytes")("address-or-contract-hex",
                                 po::value<std::string>()->default_value(""),
                                 "destination bytes hex")(
      "destination-enabled", po::value<bool>()->default_value(true),
      "destination enabled")("destination-label", po::value<std::string>(),
                             "destination label hex")(
      "approver", po::value<std::vector<std::string>>()->multitoken(),
      "approver signer hash32 values")("threshold",
                                       po::value<uint32_t>()->default_value(1),
                                       "approval threshold")(
      "required-approvals", po::value<uint32_t>()->default_value(1),
      "destination update approval threshold")(
      "delay-ms", po::value<uint64_t>()->default_value(0),
      "destination update timelock delay ms")(
      "timelock-ms", po::value<uint64_t>()->default_value(0),
      "timelock delay ms")("limit-amount", po::value<uint64_t>(),
                           "per-transaction limit amount")(
      "require-whitelisted-destination",
      po::value<bool>()->default_value(false),
      "whether destination must be whitelisted")(
      "required-claim", po::value<std::vector<std::string>>()->multitoken(),
      "required claim names or hash32 hex")(
      "subject-id", po::value<std::string>(), "subject hash32 hex")(
      "claim", po::value<std::string>(), "claim name or hash32 hex")(
      "issuer", po::value<std::string>(), "issuer signer hash32 hex")(
      "attestation-expires-at", po::value<uint64_t>()->default_value(0),
      "attestation expires at ms")("reference-hash", po::value<std::string>(),
                                   "attestation reference hash32")(
      "scope-type", po::value<std::string>()->default_value("workspace"),
      "workspace|vault policy scope selector")(
      "subject-signer", po::value<std::string>(),
      "named signer hash32 for role subject")(
      "role", po::value<std::string>()->default_value("initiator"),
      "initiator|approver|executor|admin|auditor|guardian|attestor")(
      "role-enabled", po::value<bool>()->default_value(true),
      "whether role assignment is enabled")(
      "role-not-before", po::value<uint64_t>(),
      "role assignment not_before ms")("role-expires-at", po::value<uint64_t>(),
                                       "role assignment expires_at ms")(
      "role-note-hex", po::value<std::string>(),
      "role assignment note bytes hex")(
      "target-signer", po::value<std::string>(),
      "named signer hash32 for quarantine target")(
      "quarantined", po::value<bool>()->default_value(true),
      "whether signer should be quarantined")(
      "quarantine-until", po::value<uint64_t>(), "signer quarantine until ms")(
      "quarantine-reason-hex", po::value<std::string>(),
      "signer quarantine reason bytes hex")(
      "degraded-mode", po::value<std::string>()->default_value("normal"),
      "normal|read_only|emergency_halt")("effective-at", po::value<uint64_t>(),
                                         "degraded mode effective_at ms")(
      "degraded-reason-hex", po::value<std::string>(),
      "degraded mode reason bytes hex")("from-height",
                                        po::value<uint64_t>()->default_value(1),
                                        "history range from")(
      "to-height", po::value<uint64_t>()->default_value(1), "history range to");

  auto positional = po::positional_options_description{};
  positional.add("command", 1);
  auto vm = po::variables_map{};
  po::store(po::command_line_parser(argc, argv)
                .options(options)
                .positional(positional)
                .run(),
            vm);
  po::notify(vm);

  if (vm.contains("help") || command.empty()) {
    print_help(options);
    return 0;
  }

  if (command == "transaction" || command == "tx") {
    return run_transaction_command(vm);
  }

  if (command == "query-key") {
    return run_query_key_command(vm);
  }

  if (command == "decode-intent-state" || command == "decode-intent-status") {
    return run_decode_intent_state_command(vm);
  }

  if (command == "chain-id") {
    return run_chain_id_command();
  }

  charter::common::critical(
      "command must be transaction|query-key|decode-intent-state|chain-id");
}

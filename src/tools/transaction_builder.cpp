#include <boost/program_options.hpp>
#include <charter/blake3/hash.hpp>
#include <charter/common/critical.hpp>
#include <charter/schema/encoding/scale/encoder.hpp>
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

uint8_t hex_nibble(const char c) {
  const auto uc = static_cast<unsigned char>(c);
  if (uc >= static_cast<unsigned char>('0') &&
      uc <= static_cast<unsigned char>('9')) {
    return static_cast<uint8_t>(uc - static_cast<unsigned char>('0'));
  }
  if (uc >= static_cast<unsigned char>('a') &&
      uc <= static_cast<unsigned char>('f')) {
    return static_cast<uint8_t>(uc - static_cast<unsigned char>('a') + 10);
  }
  if (uc >= static_cast<unsigned char>('A') &&
      uc <= static_cast<unsigned char>('F')) {
    return static_cast<uint8_t>(uc - static_cast<unsigned char>('A') + 10);
  }
  charter::common::critical("invalid hex nibble");
}

std::string_view normalize_hex(std::string_view input) {
  if (input.size() >= 2 && input[0] == '0' &&
      (input[1] == 'x' || input[1] == 'X')) {
    input.remove_prefix(2);
  }
  return input;
}

charter::schema::bytes_t decode_hex_bytes(const std::string_view hex) {
  auto normalized = normalize_hex(hex);
  if ((normalized.size() % 2) != 0) {
    charter::common::critical("hex string must have even length");
  }
  auto out = charter::schema::bytes_t{};
  out.reserve(normalized.size() / 2);
  for (size_t i = 0; i < normalized.size(); i += 2) {
    auto high = hex_nibble(normalized[i]);
    auto low = hex_nibble(normalized[i + 1]);
    out.push_back(static_cast<uint8_t>((high << 4u) | low));
  }
  return out;
}

std::string encode_base64(const charter::schema::bytes_t& input) {
  static constexpr auto kTable =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  auto out = std::string{};
  out.reserve(((input.size() + 2) / 3) * 4);

  auto i = size_t{0};
  while (i + 3 <= input.size()) {
    auto value = (static_cast<uint32_t>(input[i]) << 16u) |
                 (static_cast<uint32_t>(input[i + 1]) << 8u) |
                 static_cast<uint32_t>(input[i + 2]);
    out.push_back(kTable[(value >> 18u) & 0x3Fu]);
    out.push_back(kTable[(value >> 12u) & 0x3Fu]);
    out.push_back(kTable[(value >> 6u) & 0x3Fu]);
    out.push_back(kTable[value & 0x3Fu]);
    i += 3;
  }
  if (i < input.size()) {
    auto value = static_cast<uint32_t>(input[i]) << 16u;
    out.push_back(kTable[(value >> 18u) & 0x3Fu]);
    if ((i + 1) < input.size()) {
      value |= static_cast<uint32_t>(input[i + 1]) << 8u;
      out.push_back(kTable[(value >> 12u) & 0x3Fu]);
      out.push_back(kTable[(value >> 6u) & 0x3Fu]);
      out.push_back('=');
    } else {
      out.push_back(kTable[(value >> 12u) & 0x3Fu]);
      out.push_back('=');
      out.push_back('=');
    }
  }
  return out;
}

std::string to_hex(const charter::schema::bytes_t& bytes) {
  static constexpr auto kHex = "0123456789abcdef";
  auto out = std::string{};
  out.reserve(bytes.size() * 2);
  for (const auto value : bytes) {
    out.push_back(kHex[(value >> 4u) & 0x0Fu]);
    out.push_back(kHex[value & 0x0Fu]);
  }
  return out;
}

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

charter::schema::signer_id_t make_named_signer(const po::variables_map& vm,
                                               const std::string& name) {
  return charter::schema::signer_id_t{get_hash32(vm, name)};
}

charter::schema::signature_t make_signature(const po::variables_map& vm) {
  auto kind = vm["signature-kind"].as<std::string>();
  auto bytes = vm["signature-hex"].as<std::string>().empty()
                   ? charter::schema::bytes_t{}
                   : decode_hex_bytes(vm["signature-hex"].as<std::string>());
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
  if (chain == "bitcoin") {
    return charter::schema::chain_type_t{charter::schema::chain_type::bitcoin};
  }
  if (chain == "ethereum") {
    return charter::schema::chain_type_t{charter::schema::chain_type::ethereum};
  }
  if (chain == "solana") {
    return charter::schema::chain_type_t{charter::schema::chain_type::solana};
  }
  if (chain == "eosio") {
    return charter::schema::chain_type_t{charter::schema::chain_type::eosio};
  }
  return charter::schema::chain_type_t{decode_hex_bytes(chain)};
}

charter::schema::destination_type_t parse_destination_type(
    const std::string& destination_type) {
  if (destination_type == "address") {
    return charter::schema::destination_type_t::address;
  }
  if (destination_type == "contract") {
    return charter::schema::destination_type_t::contract;
  }
  charter::common::critical("destination-type must be address|contract");
}

charter::schema::vault_model_t parse_vault_model(const std::string& model) {
  if (model == "segregated") {
    return charter::schema::vault_model_t::segregated;
  }
  if (model == "omnibus") {
    return charter::schema::vault_model_t::omnibus;
  }
  charter::common::critical("vault-model must be segregated|omnibus");
}

charter::schema::transaction_payload_t build_payload(
    const po::variables_map& vm) {
  auto payload = vm["payload"].as<std::string>();
  if (payload == "create_workspace") {
    auto admins = std::vector<charter::schema::signer_id_t>{};
    if (vm.contains("admin")) {
      for (const auto& value : vm["admin"].as<std::vector<std::string>>()) {
        admins.push_back(
            charter::schema::signer_id_t{charter::schema::make_hash32(value)});
      }
    } else {
      admins.push_back(make_named_signer(vm, "signer"));
    }
    return charter::schema::create_workspace_t{
        .workspace_id = get_hash32(vm, "workspace-id"),
        .admin_set = admins,
        .quorum_size = vm["quorum"].as<uint32_t>(),
        .metadata_ref = get_optional_hash32(vm, "metadata-ref")};
  }
  if (payload == "create_vault") {
    return charter::schema::create_vault_t{
        .workspace_id = get_hash32(vm, "workspace-id"),
        .vault_id = get_hash32(vm, "vault-id"),
        .model = parse_vault_model(vm["vault-model"].as<std::string>()),
        .label = std::nullopt};
  }
  if (payload == "upsert_destination") {
    auto label = std::optional<charter::schema::bytes_t>{};
    if (vm.contains("destination-label")) {
      label = decode_hex_bytes(vm["destination-label"].as<std::string>());
    }
    return charter::schema::upsert_destination_t{
        .workspace_id = get_hash32(vm, "workspace-id"),
        .destination_id = get_hash32(vm, "destination-id"),
        .type =
            parse_destination_type(vm["destination-type"].as<std::string>()),
        .chain_type = parse_chain_type(vm["chain"].as<std::string>()),
        .address_or_contract =
            decode_hex_bytes(vm["address-or-contract-hex"].as<std::string>()),
        .enabled = vm["destination-enabled"].as<bool>(),
        .label = label};
  }
  if (payload == "create_policy_set") {
    auto scope = charter::schema::policy_scope_t{
        charter::schema::vault_t{.workspace_id = get_hash32(vm, "workspace-id"),
                                 .vault_id = get_hash32(vm, "vault-id")}};
    auto approvers = std::vector<charter::schema::signer_id_t>{};
    if (vm.contains("approver")) {
      for (const auto& value : vm["approver"].as<std::vector<std::string>>()) {
        approvers.push_back(
            charter::schema::signer_id_t{charter::schema::make_hash32(value)});
      }
    } else {
      approvers.push_back(make_named_signer(vm, "signer"));
    }
    auto limits = std::vector<charter::schema::limit_rule_t>{};
    if (vm.contains("limit-amount")) {
      limits.push_back(charter::schema::limit_rule_t{
          .asset_id = get_hash32(vm, "asset-id"),
          .per_transaction_amount =
              charter::schema::amount_t{vm["limit-amount"].as<uint64_t>()}});
    }
    auto destination_rules = std::vector<charter::schema::destination_rule_t>{};
    if (vm["require-whitelisted-destination"].as<bool>()) {
      destination_rules.push_back(
          charter::schema::destination_rule_t{.require_whitelisted = true});
    }
    auto required_claims = std::vector<charter::schema::claim_type_t>{};
    if (vm.contains("required-claim")) {
      for (const auto& claim :
           vm["required-claim"].as<std::vector<std::string>>()) {
        required_claims.push_back(parse_claim_type(claim));
      }
    }
    auto rule = charter::schema::policy_rule_t{
        .operation = charter::schema::operation_type_t::transfer,
        .approvals = {charter::schema::approval_rule_t{
            .approver_role = charter::schema::role_id_t::approver,
            .threshold = vm["threshold"].as<uint32_t>(),
            .require_distinct_from_initiator = false,
            .require_distinct_from_executor = false}},
        .limits = limits,
        .time_locks =
            std::vector<charter::schema::time_lock_rule_t>{
                charter::schema::time_lock_rule_t{
                    .operation = charter::schema::operation_type_t::transfer,
                    .delay = vm["timelock-ms"].as<uint64_t>()}},
        .destination_rules = destination_rules,
        .required_claims = required_claims,
        .velocity_limits = {}};
    return charter::schema::create_policy_set_t{
        .policy_set_id = get_hash32(vm, "policy-set-id"),
        .scope = scope,
        .policy_version =
            static_cast<uint16_t>(vm["policy-version"].as<uint32_t>()),
        .roles = {{charter::schema::role_id_t::approver, approvers}},
        .rules = {rule}};
  }
  if (payload == "activate_policy_set") {
    return charter::schema::activate_policy_set_t{
        .scope = charter::schema::policy_scope_t{charter::schema::vault_t{
            .workspace_id = get_hash32(vm, "workspace-id"),
            .vault_id = get_hash32(vm, "vault-id")}},
        .policy_set_id = get_hash32(vm, "policy-set-id"),
        .policy_set_version = vm["policy-version"].as<uint32_t>()};
  }
  if (payload == "propose_intent") {
    return charter::schema::propose_intent_t{
        .workspace_id = get_hash32(vm, "workspace-id"),
        .vault_id = get_hash32(vm, "vault-id"),
        .intent_id = get_hash32(vm, "intent-id"),
        .action =
            charter::schema::transfer_parameters_t{
                .asset_id = get_hash32(vm, "asset-id"),
                .destination_id = get_hash32(vm, "destination-id"),
                .amount = vm["amount"].as<uint64_t>()},
        .expires_at =
            vm.contains("expires-at")
                ? std::optional<
                      charter::schema::
                          timestamp_milliseconds_t>{vm["expires-at"]
                                                        .as<uint64_t>()}
                : std::nullopt};
  }
  if (payload == "approve_intent") {
    return charter::schema::approve_intent_t{
        .workspace_id = get_hash32(vm, "workspace-id"),
        .vault_id = get_hash32(vm, "vault-id"),
        .intent_id = get_hash32(vm, "intent-id")};
  }
  if (payload == "execute_intent") {
    return charter::schema::execute_intent_t{
        .workspace_id = get_hash32(vm, "workspace-id"),
        .vault_id = get_hash32(vm, "vault-id"),
        .intent_id = get_hash32(vm, "intent-id")};
  }
  if (payload == "upsert_attestation") {
    return charter::schema::upsert_attestation_t{
        .workspace_id = get_hash32(vm, "workspace-id"),
        .subject = get_hash32(vm, "subject-id"),
        .claim = parse_claim_type(vm["claim"].as<std::string>()),
        .issuer = make_named_signer(vm, "issuer"),
        .expires_at = vm["attestation-expires-at"].as<uint64_t>(),
        .reference_hash = get_optional_hash32(vm, "reference-hash")};
  }
  if (payload == "revoke_attestation") {
    return charter::schema::revoke_attestation_t{
        .workspace_id = get_hash32(vm, "workspace-id"),
        .subject = get_hash32(vm, "subject-id"),
        .claim = parse_claim_type(vm["claim"].as<std::string>()),
        .issuer = make_named_signer(vm, "issuer")};
  }
  charter::common::critical("unsupported payload type");
}

charter::schema::bytes_t build_query_key(const po::variables_map& vm) {
  auto encoder = encoder_t{};
  auto path = vm["path"].as<std::string>();
  if (path == "/engine/info" || path == "/engine/keyspaces" ||
      path == "/history/export") {
    return {};
  }
  if (path == "/state/workspace") {
    auto hash = get_hash32(vm, "workspace-id");
    return charter::schema::bytes_t{std::begin(hash), std::end(hash)};
  }
  if (path == "/state/vault") {
    return encoder.encode(
        std::tuple{get_hash32(vm, "workspace-id"), get_hash32(vm, "vault-id")});
  }
  if (path == "/state/policy_set") {
    return encoder.encode(std::tuple{get_hash32(vm, "policy-set-id"),
                                     vm["policy-version"].as<uint32_t>()});
  }
  if (path == "/state/destination") {
    return encoder.encode(std::tuple{get_hash32(vm, "workspace-id"),
                                     get_hash32(vm, "destination-id")});
  }
  if (path == "/state/active_policy") {
    return encoder.encode(charter::schema::policy_scope_t{
        charter::schema::vault_t{.workspace_id = get_hash32(vm, "workspace-id"),
                                 .vault_id = get_hash32(vm, "vault-id")}});
  }
  if (path == "/state/intent") {
    return encoder.encode(std::tuple{get_hash32(vm, "workspace-id"),
                                     get_hash32(vm, "vault-id"),
                                     get_hash32(vm, "intent-id")});
  }
  if (path == "/state/approval") {
    return encoder.encode(std::tuple{get_hash32(vm, "intent-id"),
                                     make_named_signer(vm, "signer")});
  }
  if (path == "/state/attestation") {
    return encoder.encode(
        std::tuple{get_hash32(vm, "workspace-id"), get_hash32(vm, "subject-id"),
                   parse_claim_type(vm["claim"].as<std::string>()),
                   make_named_signer(vm, "issuer")});
  }
  if (path == "/history/range") {
    return encoder.encode(std::tuple{vm["from-height"].as<uint64_t>(),
                                     vm["to-height"].as<uint64_t>()});
  }
  if (path == "/events/range") {
    return encoder.encode(std::tuple{vm["from-height"].as<uint64_t>(),
                                     vm["to-height"].as<uint64_t>()});
  }
  charter::common::critical("unsupported query path");
}

void print_help(const po::options_description& options) {
  std::cout << "Usage:\n"
            << "  transaction_builder transaction [options]\n"
            << "  transaction_builder query-key [options]\n"
            << "  transaction_builder chain-id\n\n";
  std::cout << options << '\n';
}

}  // namespace

int main(int argc, const char** argv) {
  auto command = std::string{};
  auto options = po::options_description{"transaction_builder options"};
  options.add_options()("help,h", "show help")(
      "command", po::value<std::string>(&command),
      "transaction|query-key|chain-id")("payload", po::value<std::string>(),
                                        "transaction payload type")(
      "path", po::value<std::string>(), "abci query path")(
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
      "asset-id", po::value<std::string>(), "asset hash32 hex")(
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
      "from-height", po::value<uint64_t>()->default_value(1),
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
    if (!vm.contains("payload")) {
      charter::common::critical("transaction mode requires --payload");
    }
    auto transaction = charter::schema::transaction_t{
        .version = 1,
        .chain_id = get_hash32(vm, "chain-id"),
        .nonce = vm["nonce"].as<uint64_t>(),
        .signer = make_named_signer(vm, "signer"),
        .payload = build_payload(vm),
        .signature = make_signature(vm)};
    auto encoded = encoder_t{}.encode(transaction);
    std::cout << encode_base64(encoded) << '\n';
    return 0;
  }

  if (command == "query-key") {
    if (!vm.contains("path")) {
      charter::common::critical("query-key mode requires --path");
    }
    auto key = build_query_key(vm);
    std::cout << encode_base64(key) << '\n';
    return 0;
  }

  if (command == "chain-id") {
    auto chain_id =
        charter::blake3::hash(std::string_view{"charter-poc-chain"});
    auto bytes =
        charter::schema::bytes_t{std::begin(chain_id), std::end(chain_id)};
    std::cout << to_hex(bytes) << '\n';
    return 0;
  }

  charter::common::critical("command must be transaction|query-key|chain-id");
}

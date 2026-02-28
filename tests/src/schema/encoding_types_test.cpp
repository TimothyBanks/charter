#include <charter/schema/encoding/scale/encoder.hpp>
#include <charter/schema/create_workspace.hpp>
#include <charter/schema/destination_update_state.hpp>
#include <charter/schema/query_result.hpp>
#include <charter/schema/replay_result.hpp>
#include <charter/schema/snapshot_descriptor.hpp>
#include <charter/schema/policy_rule.hpp>
#include <charter/schema/security_event_record.hpp>
#include <charter/schema/set_degraded_mode.hpp>
#include <charter/schema/transaction.hpp>
#include <charter/schema/transaction_event.hpp>
#include <charter/schema/transaction_result.hpp>
#include <charter/schema/upsert_role_assignment.hpp>
#include <charter/schema/upsert_signer_quarantine.hpp>
#include <charter/schema/velocity_counter_state.hpp>
#include <gtest/gtest.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

charter::schema::hash32_t make_hash(const uint8_t seed) {
  auto out = charter::schema::hash32_t{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(seed + static_cast<uint8_t>(i));
  }
  return out;
}

charter::schema::signer_id_t make_ed25519_signer(const uint8_t seed) {
  auto signer = charter::schema::ed25519_signer_id{};
  for (std::size_t i = 0; i < signer.public_key.size(); ++i) {
    signer.public_key[i] = static_cast<uint8_t>(seed + static_cast<uint8_t>(i));
  }
  return signer;
}

std::string to_hex(const charter::schema::bytes_t& bytes) {
  static constexpr auto kHex = std::string_view{"0123456789abcdef"};
  auto out = std::string{};
  out.resize(bytes.size() * 2);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    out[(2 * i)] = kHex[(bytes[i] >> 4u) & 0x0Fu];
    out[(2 * i) + 1] = kHex[bytes[i] & 0x0Fu];
  }
  return out;
}

std::vector<std::pair<std::string, charter::schema::transaction_t>>
build_payload_vector_transactions() {
  auto signer = make_ed25519_signer(140);
  auto chain = make_hash(141);
  auto workspace = make_hash(142);
  auto vault = make_hash(143);
  auto destination = make_hash(144);
  auto intent = make_hash(145);
  auto policy = make_hash(146);
  auto asset = make_hash(147);
  auto update = make_hash(148);

  auto scope = charter::schema::policy_scope_t{
      charter::schema::vault_t{.workspace_id = workspace, .vault_id = vault}};
  auto transfer = charter::schema::transfer_parameters_t{
      .asset_id = asset, .destination_id = destination, .amount = 5};
  auto rule = charter::schema::policy_rule_t{
      .operation = charter::schema::operation_type_t::transfer,
      .approvals = {},
      .limits = {},
      .time_locks = {},
      .destination_rules = {},
      .required_claims = {},
      .velocity_limits = {}};

  auto build_transaction = [&](const uint64_t nonce,
                      const charter::schema::transaction_payload_t& payload) {
    return charter::schema::transaction_t{
        .version = 1,
        .chain_id = chain,
        .nonce = nonce,
        .signer = signer,
        .payload = payload,
        .signature = charter::schema::ed25519_signature_t{}};
  };

  auto txs = std::vector<std::pair<std::string, charter::schema::transaction_t>>{};
  txs.push_back({"create_workspace",
                 build_transaction(1, charter::schema::create_workspace_t{
                                 .workspace_id = workspace,
                                 .admin_set = {signer},
                                 .quorum_size = 1,
                                 .metadata_ref = std::nullopt})});
  txs.push_back({"create_vault",
                 build_transaction(2, charter::schema::create_vault_t{
                                 .workspace_id = workspace,
                                 .vault_id = vault,
                                 .model = charter::schema::vault_model_t::segregated,
                                 .label = std::nullopt})});
  txs.push_back({"upsert_destination",
                 build_transaction(3, charter::schema::upsert_destination_t{
                                 .workspace_id = workspace,
                                 .destination_id = destination,
                                 .type = charter::schema::destination_type_t::address,
                                 .chain_type = charter::schema::chain_type_t{
                                     charter::schema::chain_type::ethereum},
                                 .address_or_contract = charter::schema::bytes_t{0x01, 0x02},
                                 .enabled = true,
                                 .label = std::nullopt})});
  txs.push_back({"create_policy_set",
                 build_transaction(4, charter::schema::create_policy_set_t{
                                 .policy_set_id = policy,
                                 .scope = scope,
                                 .policy_version = 1,
                                 .roles = {{charter::schema::role_id_t::approver, {signer}}},
                                 .rules = {rule}})});
  txs.push_back({"activate_policy_set",
                 build_transaction(5, charter::schema::activate_policy_set_t{
                                 .scope = scope,
                                 .policy_set_id = policy,
                                 .policy_set_version = 1})});
  txs.push_back({"propose_intent",
                 build_transaction(6, charter::schema::propose_intent_t{
                                 .workspace_id = workspace,
                                 .vault_id = vault,
                                 .intent_id = intent,
                                 .action = transfer,
                                 .expires_at = std::nullopt})});
  txs.push_back({"approve_intent",
                 build_transaction(7, charter::schema::approve_intent_t{
                                 .workspace_id = workspace,
                                 .vault_id = vault,
                                 .intent_id = intent})});
  txs.push_back({"execute_intent",
                 build_transaction(8, charter::schema::execute_intent_t{
                                 .workspace_id = workspace,
                                 .vault_id = vault,
                                 .intent_id = intent})});
  txs.push_back({"cancel_intent",
                 build_transaction(9, charter::schema::cancel_intent_t{
                                 .workspace_id = workspace,
                                 .vault_id = vault,
                                 .intent_id = intent})});
  txs.push_back({"upsert_attestation",
                 build_transaction(10, charter::schema::upsert_attestation_t{
                                  .workspace_id = workspace,
                                  .subject = workspace,
                                  .claim = charter::schema::claim_type_t{
                                      charter::schema::claim_type::kyb_verified},
                                  .issuer = signer,
                                  .expires_at = 1700000000000ULL,
                                  .reference_hash = make_hash(149)})});
  txs.push_back({"revoke_attestation",
                 build_transaction(11, charter::schema::revoke_attestation_t{
                                  .workspace_id = workspace,
                                  .subject = workspace,
                                  .claim = charter::schema::claim_type_t{
                                      charter::schema::claim_type::kyb_verified},
                                  .issuer = signer})});
  txs.push_back({"set_degraded_mode",
                 build_transaction(12, charter::schema::set_degraded_mode_t{
                                  .mode = charter::schema::degraded_mode_t::read_only,
                                  .effective_at = 1700000000001ULL,
                                  .reason = charter::schema::make_bytes(
                                      std::string_view{"incident"})})});
  txs.push_back({"upsert_role_assignment",
                 build_transaction(13, charter::schema::upsert_role_assignment_t{
                                  .scope = scope,
                                  .subject = signer,
                                  .role = charter::schema::role_id_t::approver,
                                  .enabled = true,
                                  .not_before = std::nullopt,
                                  .expires_at = std::nullopt,
                                  .note = charter::schema::make_bytes(
                                      std::string_view{"grant"})})});
  txs.push_back({"upsert_signer_quarantine",
                 build_transaction(14, charter::schema::upsert_signer_quarantine_t{
                                  .signer = signer,
                                  .quarantined = true,
                                  .until = 1700000000002ULL,
                                  .reason = charter::schema::make_bytes(
                                      std::string_view{"alert"})})});
  txs.push_back({"propose_destination_update",
                 build_transaction(15, charter::schema::propose_destination_update_t{
                                  .workspace_id = workspace,
                                  .destination_id = destination,
                                  .update_id = update,
                                  .type = charter::schema::destination_type_t::address,
                                  .chain_type = charter::schema::chain_type_t{
                                      charter::schema::chain_type::ethereum},
                                  .address_or_contract = charter::schema::bytes_t{0xAA},
                                  .enabled = true,
                                  .label = charter::schema::make_bytes(
                                      std::string_view{"new-dst"}),
                                  .required_approvals = 1,
                                  .delay_ms = 0})});
  txs.push_back({"approve_destination_update",
                 build_transaction(16, charter::schema::approve_destination_update_t{
                                  .workspace_id = workspace,
                                  .destination_id = destination,
                                  .update_id = update})});
  txs.push_back({"apply_destination_update",
                 build_transaction(17, charter::schema::apply_destination_update_t{
                                  .workspace_id = workspace,
                                  .destination_id = destination,
                                  .update_id = update})});
  return txs;
}

}  // namespace

TEST(schema_encoding_types, security_event_record_round_trips) {
  using charter::schema::encoding::encoder;
  using charter::schema::encoding::scale_encoder_tag;

  auto input = charter::schema::security_event_record_t{};
  input.event_id = 77;
  input.height = 1234;
  input.tx_index = 3;
  input.type = charter::schema::security_event_type_t::tx_execution_denied;
  input.severity = charter::schema::security_event_severity_t::warning;
  input.code = 31;
  input.message =
      charter::schema::make_bytes(std::string_view{"quarantined signer"});
  input.signer = make_ed25519_signer(10);
  input.workspace_id = make_hash(20);
  input.vault_id = make_hash(40);
  input.recorded_at = 1700000000000ULL;

  auto codec = encoder<scale_encoder_tag>{};
  const auto encoded = codec.encode(input);
  const auto decoded = codec.decode<charter::schema::security_event_record_t>(
      charter::schema::make_bytes_view(encoded));

  EXPECT_EQ(decoded.version, input.version);
  EXPECT_EQ(decoded.event_id, input.event_id);
  EXPECT_EQ(decoded.height, input.height);
  EXPECT_EQ(decoded.tx_index, input.tx_index);
  EXPECT_EQ(decoded.type, input.type);
  EXPECT_EQ(decoded.severity, input.severity);
  EXPECT_EQ(decoded.code, input.code);
  EXPECT_EQ(decoded.message, input.message);
  ASSERT_TRUE(decoded.workspace_id.has_value());
  ASSERT_TRUE(decoded.vault_id.has_value());
  EXPECT_EQ(decoded.workspace_id.value(), input.workspace_id.value());
  EXPECT_EQ(decoded.vault_id.value(), input.vault_id.value());
  ASSERT_TRUE(decoded.signer.has_value());
  ASSERT_TRUE(input.signer.has_value());
  ASSERT_TRUE(std::holds_alternative<charter::schema::ed25519_signer_id>(
      decoded.signer.value()));
  EXPECT_EQ(std::get<charter::schema::ed25519_signer_id>(decoded.signer.value())
                .public_key,
            std::get<charter::schema::ed25519_signer_id>(input.signer.value())
                .public_key);
  EXPECT_EQ(decoded.recorded_at, input.recorded_at);
}

TEST(schema_encoding_types, policy_rule_round_trips_velocity_limits) {
  using charter::schema::encoding::encoder;
  using charter::schema::encoding::scale_encoder_tag;

  auto velocity = charter::schema::velocity_limit_rule_t{};
  velocity.operation = charter::schema::operation_type_t::transfer;
  velocity.asset_id = make_hash(50);
  velocity.window = charter::schema::velocity_window_t::daily;
  velocity.maximum_amount = 500;

  auto policy = charter::schema::policy_rule_t{};
  policy.operation = charter::schema::operation_type_t::transfer;
  policy.velocity_limits.push_back(velocity);

  auto codec = encoder<scale_encoder_tag>{};
  const auto encoded = codec.encode(policy);
  const auto decoded =
      codec.decode<charter::schema::policy_rule_t>(
          charter::schema::make_bytes_view(encoded));

  EXPECT_EQ(decoded.operation, charter::schema::operation_type_t::transfer);
  ASSERT_EQ(decoded.velocity_limits.size(), 1u);
  EXPECT_EQ(decoded.velocity_limits.front().operation, velocity.operation);
  ASSERT_TRUE(decoded.velocity_limits.front().asset_id.has_value());
  EXPECT_EQ(decoded.velocity_limits.front().asset_id.value(),
            velocity.asset_id.value());
  EXPECT_EQ(decoded.velocity_limits.front().window, velocity.window);
  EXPECT_EQ(decoded.velocity_limits.front().maximum_amount, velocity.maximum_amount);
}

TEST(schema_encoding_types, engine_wire_types_round_trip) {
  using charter::schema::encoding::encoder;
  using charter::schema::encoding::scale_encoder_tag;

  auto event = charter::schema::transaction_event_t{};
  event.type = "charter.tx_result";
  event.attributes.push_back(
      charter::schema::transaction_event_attribute_t{.key = "code",
                                            .value = "33",
                                            .index = true});
  auto tx = charter::schema::transaction_result_t{};
  tx.code = 33;
  tx.log = "authorization denied";
  tx.events.push_back(event);

  auto query = charter::schema::query_result_t{};
  query.code = 7;
  query.key = charter::schema::make_bytes(std::string_view{"k"});
  query.value = charter::schema::make_bytes(std::string_view{"v"});

  auto replay = charter::schema::replay_result_t{};
  replay.ok = true;
  replay.tx_count = 9;
  replay.applied_count = 8;
  replay.state_root = make_hash(21);

  auto snapshot = charter::schema::snapshot_descriptor_t{};
  snapshot.height = 10;
  snapshot.hash = make_hash(22);
  snapshot.metadata = charter::schema::make_bytes(std::string_view{"meta"});

  auto codec = encoder<scale_encoder_tag>{};

  auto decoded_tx = codec.decode<charter::schema::transaction_result_t>(
      charter::schema::make_bytes_view(codec.encode(tx)));
  EXPECT_EQ(decoded_tx.code, tx.code);
  ASSERT_EQ(decoded_tx.events.size(), 1u);
  EXPECT_EQ(decoded_tx.events.front().type, event.type);

  auto decoded_query = codec.decode<charter::schema::query_result_t>(
      charter::schema::make_bytes_view(codec.encode(query)));
  EXPECT_EQ(decoded_query.code, query.code);
  EXPECT_EQ(decoded_query.value, query.value);

  auto decoded_replay = codec.decode<charter::schema::replay_result_t>(
      charter::schema::make_bytes_view(codec.encode(replay)));
  EXPECT_EQ(decoded_replay.ok, replay.ok);
  EXPECT_EQ(decoded_replay.state_root, replay.state_root);

  auto decoded_snapshot = codec.decode<charter::schema::snapshot_descriptor_t>(
      charter::schema::make_bytes_view(codec.encode(snapshot)));
  EXPECT_EQ(decoded_snapshot.height, snapshot.height);
  EXPECT_EQ(decoded_snapshot.hash, snapshot.hash);
}

TEST(schema_encoding_types, transaction_payload_supports_new_admin_operations) {
  auto tx = charter::schema::transaction_t{};

  tx.payload = charter::schema::set_degraded_mode_t{};
  EXPECT_TRUE(std::holds_alternative<charter::schema::set_degraded_mode_t>(
      tx.payload));

  tx.payload = charter::schema::upsert_role_assignment_t{};
  EXPECT_TRUE(std::holds_alternative<charter::schema::upsert_role_assignment_t>(
      tx.payload));

  tx.payload = charter::schema::upsert_signer_quarantine_t{};
  EXPECT_TRUE(
      std::holds_alternative<charter::schema::upsert_signer_quarantine_t>(
          tx.payload));

  tx.payload = charter::schema::propose_destination_update_t{};
  EXPECT_TRUE(
      std::holds_alternative<charter::schema::propose_destination_update_t>(
          tx.payload));

  tx.payload = charter::schema::approve_destination_update_t{};
  EXPECT_TRUE(
      std::holds_alternative<charter::schema::approve_destination_update_t>(
          tx.payload));

  tx.payload = charter::schema::apply_destination_update_t{};
  EXPECT_TRUE(
      std::holds_alternative<charter::schema::apply_destination_update_t>(
          tx.payload));
}

TEST(schema_encoding_types, transaction_golden_vector_create_workspace_v1) {
  using charter::schema::encoding::encoder;
  using charter::schema::encoding::scale_encoder_tag;

  auto chain_id = charter::schema::make_hash32(
      std::string_view{"f049f55aa11129a9aa953b3c7ae03e106043eb600cb5cfa35b80da0615d08ae9"});
  auto signer_hash = charter::schema::make_hash32(
      std::string_view{"1111111111111111111111111111111111111111111111111111111111111111"});
  auto workspace_id = charter::schema::make_hash32(
      std::string_view{"2222222222222222222222222222222222222222222222222222222222222222"});

  auto tx = charter::schema::transaction_t{};
  tx.chain_id = chain_id;
  tx.nonce = 7;
  tx.signer = signer_hash;
  tx.payload = charter::schema::create_workspace_t{
      .workspace_id = workspace_id,
      .admin_set = {charter::schema::signer_id_t{signer_hash}},
      .quorum_size = 1,
      .metadata_ref = std::nullopt};
  tx.signature = charter::schema::ed25519_signature_t{};

  auto codec = encoder<scale_encoder_tag>{};
  auto encoded = codec.encode(tx);
  auto hex = to_hex(encoded);
  auto prefix = std::string{
      "0100f049f55aa11129a9aa953b3c7ae03e106043eb600cb5cfa35b80da0615d08ae9"
      "0700000000000000021111111111111111111111111111111111111111111111111111111111111111"
      "0601002222222222222222222222222222222222222222222222222222222222222222"
      "04021111111111111111111111111111111111111111111111111111111111111111"
      "01"};
  EXPECT_TRUE(hex.starts_with(prefix));
  EXPECT_EQ(encoded.size() * 2, hex.size());
}

TEST(schema_encoding_types, destination_update_state_round_trips) {
  using charter::schema::encoding::encoder;
  using charter::schema::encoding::scale_encoder_tag;

  auto state = charter::schema::destination_update_state_t{};
  state.workspace_id = make_hash(60);
  state.destination_id = make_hash(61);
  state.update_id = make_hash(62);
  state.type = charter::schema::destination_type_t::address;
  state.chain_type =
      charter::schema::chain_type_t{charter::schema::chain_type::ethereum};
  state.address_or_contract = charter::schema::bytes_t{0xAA, 0xBB, 0xCC};
  state.enabled = true;
  state.label = charter::schema::make_bytes(std::string_view{"hot-wallet"});
  state.created_by = make_ed25519_signer(71);
  state.created_at = 1700000001000ULL;
  state.not_before = 1700000002000ULL;
  state.required_approvals = 2;
  state.approvals_count = 1;
  state.status = charter::schema::destination_update_status_t::pending_approval;

  auto codec = encoder<scale_encoder_tag>{};
  auto encoded = codec.encode(state);
  auto decoded = codec.decode<charter::schema::destination_update_state_t>(
      charter::schema::make_bytes_view(encoded));

  EXPECT_EQ(decoded.workspace_id, state.workspace_id);
  EXPECT_EQ(decoded.destination_id, state.destination_id);
  EXPECT_EQ(decoded.update_id, state.update_id);
  EXPECT_EQ(decoded.type, state.type);
  EXPECT_EQ(decoded.chain_type, state.chain_type);
  EXPECT_EQ(decoded.address_or_contract, state.address_or_contract);
  EXPECT_EQ(decoded.enabled, state.enabled);
  EXPECT_EQ(decoded.label, state.label);
  ASSERT_TRUE(std::holds_alternative<charter::schema::ed25519_signer_id>(
      decoded.created_by));
  EXPECT_EQ(decoded.created_at, state.created_at);
  EXPECT_EQ(decoded.not_before, state.not_before);
  EXPECT_EQ(decoded.required_approvals, state.required_approvals);
  EXPECT_EQ(decoded.approvals_count, state.approvals_count);
  EXPECT_EQ(decoded.status, state.status);
}

TEST(schema_encoding_types, admin_state_types_round_trip) {
  using charter::schema::encoding::encoder;
  using charter::schema::encoding::scale_encoder_tag;

  auto codec = encoder<scale_encoder_tag>{};
  auto signer = make_ed25519_signer(80);

  auto role_assignment = charter::schema::role_assignment_state_t{};
  role_assignment.scope = charter::schema::policy_scope_t{
      charter::schema::vault_t{.workspace_id = make_hash(81), .vault_id = make_hash(82)}};
  role_assignment.subject = signer;
  role_assignment.role = charter::schema::role_id_t::approver;
  role_assignment.enabled = true;
  role_assignment.not_before = 1700000100000ULL;
  role_assignment.expires_at = 1700000200000ULL;
  role_assignment.note = charter::schema::make_bytes(std::string_view{"temp grant"});
  auto encoded_role = codec.encode(role_assignment);
  auto decoded_role = codec.decode<charter::schema::role_assignment_state_t>(
      charter::schema::make_bytes_view(encoded_role));
  EXPECT_EQ(decoded_role.role, role_assignment.role);
  EXPECT_EQ(decoded_role.enabled, role_assignment.enabled);
  EXPECT_EQ(decoded_role.not_before, role_assignment.not_before);
  EXPECT_EQ(decoded_role.expires_at, role_assignment.expires_at);
  EXPECT_EQ(decoded_role.note, role_assignment.note);

  auto quarantine = charter::schema::signer_quarantine_state_t{};
  quarantine.signer = signer;
  quarantine.quarantined = true;
  quarantine.until = 1700000300000ULL;
  quarantine.reason = charter::schema::make_bytes(std::string_view{"incident"});
  auto encoded_quarantine = codec.encode(quarantine);
  auto decoded_quarantine =
      codec.decode<charter::schema::signer_quarantine_state_t>(
          charter::schema::make_bytes_view(encoded_quarantine));
  EXPECT_EQ(decoded_quarantine.quarantined, quarantine.quarantined);
  EXPECT_EQ(decoded_quarantine.until, quarantine.until);
  EXPECT_EQ(decoded_quarantine.reason, quarantine.reason);

  auto degraded = charter::schema::degraded_mode_state_t{};
  degraded.mode = charter::schema::degraded_mode_t::read_only;
  degraded.effective_at = 1700000400000ULL;
  degraded.reason = charter::schema::make_bytes(std::string_view{"maintenance"});
  auto encoded_degraded = codec.encode(degraded);
  auto decoded_degraded = codec.decode<charter::schema::degraded_mode_state_t>(
      charter::schema::make_bytes_view(encoded_degraded));
  EXPECT_EQ(decoded_degraded.mode, degraded.mode);
  EXPECT_EQ(decoded_degraded.effective_at, degraded.effective_at);
  EXPECT_EQ(decoded_degraded.reason, degraded.reason);
}

TEST(schema_encoding_types, velocity_counter_state_round_trips) {
  using charter::schema::encoding::encoder;
  using charter::schema::encoding::scale_encoder_tag;

  auto state = charter::schema::velocity_counter_state_t{};
  state.workspace_id = make_hash(90);
  state.vault_id = make_hash(91);
  state.asset_id = make_hash(92);
  state.window = charter::schema::velocity_window_t::daily;
  state.window_start = 1700000500000ULL;
  state.used_amount = 1234;
  state.tx_count = 7;

  auto codec = encoder<scale_encoder_tag>{};
  auto encoded = codec.encode(state);
  auto decoded = codec.decode<charter::schema::velocity_counter_state_t>(
      charter::schema::make_bytes_view(encoded));

  EXPECT_EQ(decoded.workspace_id, state.workspace_id);
  EXPECT_EQ(decoded.vault_id, state.vault_id);
  EXPECT_EQ(decoded.asset_id, state.asset_id);
  EXPECT_EQ(decoded.window, state.window);
  EXPECT_EQ(decoded.window_start, state.window_start);
  EXPECT_EQ(decoded.used_amount, state.used_amount);
  EXPECT_EQ(decoded.tx_count, state.tx_count);
}

TEST(schema_encoding_types, encode_overload_appends_exact_payload_bytes) {
  using charter::schema::encoding::encoder;
  using charter::schema::encoding::scale_encoder_tag;

  auto state = charter::schema::velocity_counter_state_t{};
  state.workspace_id = make_hash(100);
  state.vault_id = make_hash(101);
  state.asset_id = make_hash(102);
  state.window = charter::schema::velocity_window_t::weekly;
  state.window_start = 1700000600000ULL;
  state.used_amount = 999;
  state.tx_count = 12;

  auto codec = encoder<scale_encoder_tag>{};
  auto encoded = codec.encode(state);

  auto out = charter::schema::bytes_t{0xDE, 0xAD, 0xBE, 0xEF};
  codec.encode(state, out);

  ASSERT_EQ(out.size(), (4u + encoded.size()));
  EXPECT_EQ(out[0], 0xDE);
  EXPECT_EQ(out[1], 0xAD);
  EXPECT_EQ(out[2], 0xBE);
  EXPECT_EQ(out[3], 0xEF);
  EXPECT_TRUE(std::equal(std::begin(encoded), std::end(encoded),
                         std::begin(out) + 4));
}

TEST(schema_encoding_types, encoding_is_deterministic_for_identical_inputs) {
  using charter::schema::encoding::encoder;
  using charter::schema::encoding::scale_encoder_tag;

  auto tx = charter::schema::transaction_t{};
  tx.chain_id = make_hash(110);
  tx.nonce = 42;
  tx.signer = make_ed25519_signer(111);
  tx.payload = charter::schema::set_degraded_mode_t{
      .version = 1,
      .mode = charter::schema::degraded_mode_t::read_only,
      .effective_at = 1700000700000ULL,
      .reason = charter::schema::make_bytes(std::string_view{"incident"})};
  tx.signature = charter::schema::ed25519_signature_t{};

  auto codec = encoder<scale_encoder_tag>{};
  auto first = codec.encode(tx);
  auto second = codec.encode(tx);
  EXPECT_EQ(first, second);
}

TEST(schema_encoding_types, try_decode_rejects_truncated_bytes) {
  using charter::schema::encoding::encoder;
  using charter::schema::encoding::scale_encoder_tag;

  auto tx = charter::schema::transaction_t{};
  tx.chain_id = make_hash(120);
  tx.nonce = 9;
  tx.signer = make_ed25519_signer(121);
  tx.payload = charter::schema::upsert_signer_quarantine_t{
      .version = 1,
      .signer = make_ed25519_signer(122),
      .quarantined = true,
      .until = 1700000800000ULL,
      .reason = charter::schema::make_bytes(std::string_view{"test"})};
  tx.signature = charter::schema::ed25519_signature_t{};

  auto codec = encoder<scale_encoder_tag>{};
  auto encoded = codec.encode(tx);
  ASSERT_GT(encoded.size(), 8u);
  encoded.resize(encoded.size() - 5);

  auto decoded = codec.try_decode<charter::schema::transaction_t>(
      charter::schema::make_bytes_view(encoded));
  EXPECT_FALSE(decoded.has_value());
}

TEST(schema_encoding_types, try_decode_rejects_random_garbage_bytes) {
  using charter::schema::encoding::encoder;
  using charter::schema::encoding::scale_encoder_tag;

  auto codec = encoder<scale_encoder_tag>{};
  auto encoded = charter::schema::bytes_t{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01};

  auto decoded = codec.try_decode<charter::schema::transaction_t>(
      charter::schema::make_bytes_view(encoded));
  EXPECT_FALSE(decoded.has_value());
}

TEST(schema_encoding_types, transaction_round_trips_all_payload_variants) {
  using charter::schema::encoding::encoder;
  using charter::schema::encoding::scale_encoder_tag;

  auto txs = build_payload_vector_transactions();

  auto codec = encoder<scale_encoder_tag>{};
  for (const auto& [name, tx] : txs) {
    auto encoded = codec.encode(tx);
    auto decoded = codec.decode<charter::schema::transaction_t>(
        charter::schema::make_bytes_view(encoded));

    SCOPED_TRACE(name);
    EXPECT_EQ(decoded.version, tx.version);
    EXPECT_EQ(decoded.chain_id, tx.chain_id);
    EXPECT_EQ(decoded.nonce, tx.nonce);
    EXPECT_EQ(codec.encode(decoded.signer), codec.encode(tx.signer));
    EXPECT_EQ(decoded.signature.index(), tx.signature.index());
    EXPECT_EQ(decoded.payload.index(), tx.payload.index());
    EXPECT_EQ(codec.encode(decoded), encoded);
  }
}

TEST(schema_encoding_types, transaction_payload_vectors_match_fixture_v1) {
  using charter::schema::encoding::encoder;
  using charter::schema::encoding::scale_encoder_tag;

  auto fixture_path = std::filesystem::path{
      "tests/fixtures/schema_payload_transaction_vectors_v1.txt"};
  if (!std::filesystem::exists(fixture_path)) {
    fixture_path = std::filesystem::path{
        "../tests/fixtures/schema_payload_transaction_vectors_v1.txt"};
  }
  auto fixture = std::ifstream{fixture_path};
  ASSERT_TRUE(fixture.is_open());

  auto expected = std::map<std::string, std::string>{};
  for (auto line = std::string{}; std::getline(fixture, line);) {
    if (line.empty()) {
      continue;
    }
    auto row = std::istringstream{line};
    auto name = std::string{};
    auto hex = std::string{};
    row >> name >> hex;
    ASSERT_FALSE(name.empty());
    ASSERT_FALSE(hex.empty());
    expected.emplace(std::move(name), std::move(hex));
  }

  auto txs = build_payload_vector_transactions();
  ASSERT_EQ(expected.size(), txs.size());

  auto codec = encoder<scale_encoder_tag>{};
  for (const auto& [name, tx] : txs) {
    auto it = expected.find(name);
    ASSERT_NE(it, expected.end()) << name;
    auto encoded = codec.encode(tx);
    EXPECT_EQ(to_hex(encoded), it->second) << name;
  }
}

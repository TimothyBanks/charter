#include <charter/execution/engine.hpp>
#include <charter/schema/active_policy_pointer.hpp>
#include <charter/schema/encoding/scale/encoder.hpp>
#include <charter/schema/intent_state.hpp>
#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <algorithm>
#include <optional>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace {

using encoder_t =
    charter::schema::encoding::encoder<charter::schema::encoding::scale_encoder_tag>;

charter::schema::hash32_t make_hash(uint8_t seed) {
  auto value = charter::schema::hash32_t{};
  for (size_t i = 0; i < value.size(); ++i) {
    value[i] = static_cast<uint8_t>(seed + i);
  }
  return value;
}

charter::schema::signer_id_t make_named_signer(uint8_t seed) {
  auto named = charter::schema::named_signer_t{};
  named[0] = seed;
  return charter::schema::signer_id_t{named};
}

charter::schema::transaction_t make_tx(
    const charter::schema::hash32_t &chain_id, uint64_t nonce,
    const charter::schema::signer_id_t &signer,
    const charter::schema::transaction_payload_t &payload) {
  return charter::schema::transaction_t{
      .version = 1,
      .chain_id = chain_id,
      .nonce = nonce,
      .signer = signer,
      .payload = payload,
      .signature = charter::schema::ed25519_signature_t{}};
}

charter::schema::bytes_t encode_tx(const charter::schema::transaction_t &tx) {
  auto encoder = encoder_t{};
  return encoder.encode(tx);
}

charter::schema::hash32_t chain_id_from_engine(charter::execution::engine &engine) {
  auto query = engine.query("/engine/info", {});
  EXPECT_EQ(query.code, 0u);
  auto encoder = encoder_t{};
  auto decoded = encoder.decode<std::tuple<int64_t, charter::schema::hash32_t,
                                           charter::schema::hash32_t>>(
      charter::schema::bytes_view_t{query.value.data(), query.value.size()});
  return std::get<2>(decoded);
}

charter::execution::tx_result finalize_single(
    charter::execution::engine& engine, const uint64_t height,
    const charter::schema::transaction_t& tx) {
  auto signer_nonce_key = [](const charter::schema::signer_id_t& signer) {
    auto key = std::string{};
    std::visit(
        overloaded{
            [&](const charter::schema::ed25519_signer_id& value) {
              key.push_back(static_cast<char>(0));
              key.append(reinterpret_cast<const char*>(value.public_key.data()),
                         value.public_key.size());
            },
            [&](const charter::schema::secp256k1_signer_id& value) {
              key.push_back(static_cast<char>(1));
              key.append(reinterpret_cast<const char*>(value.public_key.data()),
                         value.public_key.size());
            },
            [&](const charter::schema::named_signer_t& value) {
              key.push_back(static_cast<char>(2));
              key.append(reinterpret_cast<const char*>(value.data()), value.size());
            }},
        signer);
    return key;
  };
  static auto nonce_state =
      std::map<std::uintptr_t, std::map<std::string, uint64_t>>{};
  auto engine_key = reinterpret_cast<std::uintptr_t>(&engine);
  auto signer_key = signer_nonce_key(tx.signer);
  auto& signer_nonces = nonce_state[engine_key];
  auto& expected = signer_nonces[signer_key];
  if (expected == 0) {
    expected = tx.nonce;
  }

  auto normalized = tx;
  normalized.nonce = expected;
  auto block = engine.finalize_block(height, {encode_tx(normalized)});
  EXPECT_EQ(block.tx_results.size(), 1u);
  auto result = block.tx_results.front();
  if (result.code == 0) {
    ++expected;
  }
  (void)engine.commit();
  return result;
}

std::vector<charter::schema::security_event_record_t> query_events(
    charter::execution::engine& engine, const uint64_t from_id,
    const uint64_t to_id) {
  auto encoder = encoder_t{};
  auto query_key = encoder.encode(std::tuple{from_id, to_id});
  auto result = engine.query(
      "/events/range",
      charter::schema::bytes_view_t{query_key.data(), query_key.size()});
  EXPECT_EQ(result.code, 0u);
  return encoder.decode<std::vector<charter::schema::security_event_record_t>>(
      charter::schema::bytes_view_t{result.value.data(), result.value.size()});
}

charter::schema::bytes_t make_state_backup(
    const charter::schema::hash32_t& chain_id,
    const std::vector<charter::storage::key_value_entry_t>& state_rows) {
  auto encoder = encoder_t{};
  auto history_rows = std::vector<charter::storage::key_value_entry_t>{};
  auto snapshots = std::vector<charter::storage::key_value_entry_t>{};
  return encoder.encode(std::tuple{
      uint16_t{1},
      std::optional<charter::storage::committed_state>{},
      state_rows,
      history_rows,
      snapshots,
      chain_id});
}

charter::schema::bytes_t prefixed_key(
    const std::string_view prefix, const charter::schema::bytes_t& suffix) {
  auto out = charter::schema::make_bytes(prefix);
  out.insert(std::end(out), std::begin(suffix), std::end(suffix));
  return out;
}

std::string make_db_path(const std::string &prefix) {
  auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  auto path = std::filesystem::temp_directory_path() /
              (prefix + "_" + std::to_string(static_cast<unsigned long long>(now)));
  return path.string();
}

charter::schema::policy_rule_t make_transfer_rule(
    const charter::schema::hash32_t &asset_id, uint32_t threshold,
    uint64_t timelock_ms,
    std::optional<uint64_t> limit_amount = std::nullopt,
    bool require_whitelist = false,
    std::vector<charter::schema::claim_type_t> required_claims = {}) {
  auto approval = charter::schema::approval_rule_t{
      .approver_role = charter::schema::role_id_t::approver,
      .threshold = threshold,
      .require_distinct_from_initiator = false,
      .require_distinct_from_executor = false};
  auto time_lock = charter::schema::time_lock_rule_t{
      .operation = charter::schema::operation_type_t::transfer,
      .delay = timelock_ms};
  return charter::schema::policy_rule_t{
      .operation = charter::schema::operation_type_t::transfer,
      .approvals = {approval},
      .limits = limit_amount.has_value()
                    ? std::vector<charter::schema::limit_rule_t>{
                          charter::schema::limit_rule_t{
                              .asset_id = asset_id,
                              .per_transaction_amount =
                                  charter::schema::amount_t{limit_amount.value()}}}
                    : std::vector<charter::schema::limit_rule_t>{},
      .time_locks = std::vector{time_lock},
      .destination_rules =
          require_whitelist
              ? std::vector<charter::schema::destination_rule_t>{
                    charter::schema::destination_rule_t{
                        .require_whitelisted = true}}
              : std::vector<charter::schema::destination_rule_t>{},
      .reqired_claims = std::move(required_claims),
      .velocity_limits = {}};
}

} // namespace

TEST(engine_integration, backup_replay_and_state_queries_work) {
  auto db1 = make_db_path("charter_engine_it_1");
  auto db2 = make_db_path("charter_engine_it_2");

  auto signer = make_named_signer(11);
  auto workspace_id = make_hash(1);
  auto vault_id = make_hash(2);
  auto policy_set_id = make_hash(3);
  auto intent_id = make_hash(4);
  auto asset_id = make_hash(5);
  auto destination_id = make_hash(8);
  auto subject = make_hash(6);
  auto reference_hash = make_hash(7);

  auto scope = charter::schema::policy_scope_t{
      charter::schema::vault_t{.workspace_id = workspace_id, .vault_id = vault_id}};

  {
    auto engine = charter::execution::engine{1, db1, false};
    engine.set_signature_verifier([](const charter::schema::bytes_view_t &,
                                     const charter::schema::signer_id_t &,
                                     const charter::schema::signature_t &) {
      return true;
    });
    auto chain_id = chain_id_from_engine(engine);

    auto txs = std::vector<charter::schema::bytes_t>{};
    txs.push_back(encode_tx(make_tx(
        chain_id, 1, signer,
        charter::schema::create_workspace_t{
            .workspace_id = workspace_id,
            .admin_set = {signer},
            .quorum_size = 1,
            .metadata_ref = std::nullopt})));
    txs.push_back(encode_tx(make_tx(
        chain_id, 2, signer,
        charter::schema::create_vault_t{.workspace_id = workspace_id,
                                        .vault_id = vault_id,
                                        .model = charter::schema::vault_model_t::segregated,
                                        .label = std::nullopt})));
    txs.push_back(encode_tx(make_tx(
        chain_id, 3, signer,
        charter::schema::upsert_destination_t{
            .workspace_id = workspace_id,
            .destination_id = destination_id,
            .type = charter::schema::destination_type_t::address,
            .chain_type = charter::schema::chain_type_t{
                charter::schema::chain_type::ethereum},
            .address_or_contract = charter::schema::bytes_t{0x01, 0x02},
            .enabled = true,
            .label = std::nullopt})));
    txs.push_back(encode_tx(make_tx(
        chain_id, 4, signer,
        charter::schema::create_policy_set_t{
            .policy_set_id = policy_set_id,
            .scope = scope,
            .policy_version = 1,
            .roles = {{charter::schema::role_id_t::approver, {signer}}},
            .rules = {make_transfer_rule(asset_id, 1, 0)}})));
    txs.push_back(encode_tx(make_tx(
        chain_id, 5, signer,
        charter::schema::activate_policy_set_t{
            .scope = scope, .policy_set_id = policy_set_id, .policy_set_version = 1})));
    txs.push_back(encode_tx(make_tx(
        chain_id, 6, signer,
        charter::schema::propose_intent_t{
            .workspace_id = workspace_id,
            .vault_id = vault_id,
            .intent_id = intent_id,
            .action = charter::schema::transfer_parameters_t{
                .asset_id = asset_id,
                .destination_id = destination_id,
                .amount = 5},
            .expires_at = std::nullopt})));
    txs.push_back(encode_tx(make_tx(
        chain_id, 7, signer,
        charter::schema::approve_intent_t{
            .workspace_id = workspace_id, .vault_id = vault_id, .intent_id = intent_id})));
    txs.push_back(encode_tx(make_tx(
        chain_id, 8, signer,
        charter::schema::execute_intent_t{
            .workspace_id = workspace_id, .vault_id = vault_id, .intent_id = intent_id})));
    txs.push_back(encode_tx(make_tx(
        chain_id, 9, signer,
        charter::schema::upsert_attestation_t{
            .workspace_id = workspace_id,
            .subject = subject,
            .claim = charter::schema::claim_type_t{charter::schema::claim_type::kyb_verified},
            .issuer = signer,
            .expires_at = 9999999,
            .reference_hash = reference_hash})));

    auto block = engine.finalize_block(1, txs);
    ASSERT_EQ(block.tx_results.size(), txs.size());
    for (const auto &tx_result : block.tx_results) {
      EXPECT_EQ(tx_result.code, 0u);
    }
    auto commit = engine.commit();
    EXPECT_EQ(commit.committed_height, 1);

    auto encoder = encoder_t{};
    auto workspace_query = engine.query(
        "/state/workspace",
        charter::schema::bytes_view_t{workspace_id.data(), workspace_id.size()});
    EXPECT_EQ(workspace_query.code, 0u);

    auto vault_key = encoder.encode(std::tuple{workspace_id, vault_id});
    auto vault_query = engine.query(
        "/state/vault", charter::schema::bytes_view_t{vault_key.data(), vault_key.size()});
    EXPECT_EQ(vault_query.code, 0u);

    auto policy_key = encoder.encode(std::tuple{policy_set_id, uint32_t{1}});
    auto policy_query =
        engine.query("/state/policy_set",
                     charter::schema::bytes_view_t{policy_key.data(), policy_key.size()});
    EXPECT_EQ(policy_query.code, 0u);

    auto active_key = encoder.encode(scope);
    auto active_query = engine.query(
        "/state/active_policy",
        charter::schema::bytes_view_t{active_key.data(), active_key.size()});
    EXPECT_EQ(active_query.code, 0u);

    auto intent_key = encoder.encode(std::tuple{workspace_id, vault_id, intent_id});
    auto intent_query = engine.query(
        "/state/intent", charter::schema::bytes_view_t{intent_key.data(), intent_key.size()});
    EXPECT_EQ(intent_query.code, 0u);

    auto approval_key = encoder.encode(std::tuple{intent_id, signer});
    auto approval_query = engine.query(
        "/state/approval",
        charter::schema::bytes_view_t{approval_key.data(), approval_key.size()});
    EXPECT_EQ(approval_query.code, 0u);

    auto attestation_key = encoder.encode(std::tuple{
        workspace_id, subject,
        charter::schema::claim_type_t{charter::schema::claim_type::kyb_verified}, signer});
    auto attestation_query = engine.query(
        "/state/attestation",
        charter::schema::bytes_view_t{attestation_key.data(), attestation_key.size()});
    EXPECT_EQ(attestation_query.code, 0u);

    auto range_key = encoder.encode(std::tuple{uint64_t{1}, uint64_t{1}});
    auto history_query = engine.query(
        "/history/range",
        charter::schema::bytes_view_t{range_key.data(), range_key.size()});
    EXPECT_EQ(history_query.code, 0u);
    auto rows = encoder.decode<
        std::vector<std::tuple<uint64_t, uint32_t, uint32_t, charter::schema::bytes_t>>>(
        charter::schema::bytes_view_t{history_query.value.data(), history_query.value.size()});
    EXPECT_FALSE(rows.empty());

    auto backup = engine.export_backup();
    ASSERT_FALSE(backup.empty());
    auto replay_primary = engine.replay_history();
    EXPECT_TRUE(replay_primary.ok);
    EXPECT_EQ(replay_primary.last_height, 1);

    auto restored = charter::execution::engine{1, db2, false};
    restored.set_signature_verifier([](const charter::schema::bytes_view_t &,
                                       const charter::schema::signer_id_t &,
                                       const charter::schema::signature_t &) {
      return true;
    });
    auto error = std::string{};
    EXPECT_TRUE(restored.import_backup(
        charter::schema::bytes_view_t{backup.data(), backup.size()}, error))
        << error;
    auto restored_info = restored.info();
    EXPECT_EQ(restored_info.last_block_height, 1);
    auto restored_history = restored.history(1, 1);
    EXPECT_EQ(restored_history.size(), txs.size());
    auto replay_restored = restored.replay_history();
    EXPECT_TRUE(replay_restored.ok);
    EXPECT_EQ(replay_restored.last_height, 1);
  }

  std::error_code ec;
  std::filesystem::remove_all(db1, ec);
  std::filesystem::remove_all(db2, ec);
}

TEST(engine_integration, timelock_blocks_then_allows_execute) {
  auto db = make_db_path("charter_engine_timelock");

  auto signer = make_named_signer(21);
  auto workspace_id = make_hash(11);
  auto vault_id = make_hash(12);
  auto policy_set_id = make_hash(13);
  auto intent_id = make_hash(14);
  auto asset_id = make_hash(15);
  auto destination_id = make_hash(16);
  auto scope = charter::schema::policy_scope_t{
      charter::schema::vault_t{.workspace_id = workspace_id, .vault_id = vault_id}};

  {
    auto engine = charter::execution::engine{1, db, false};
    engine.set_signature_verifier([](const charter::schema::bytes_view_t &,
                                     const charter::schema::signer_id_t &,
                                     const charter::schema::signature_t &) {
      return true;
    });
    auto chain_id = chain_id_from_engine(engine);
    auto txs = std::vector<charter::schema::bytes_t>{};
    txs.push_back(encode_tx(make_tx(
        chain_id, 1, signer,
        charter::schema::create_workspace_t{
            .workspace_id = workspace_id,
            .admin_set = {signer},
            .quorum_size = 1,
            .metadata_ref = std::nullopt})));
    txs.push_back(encode_tx(make_tx(
        chain_id, 2, signer,
        charter::schema::create_vault_t{.workspace_id = workspace_id,
                                        .vault_id = vault_id,
                                        .model = charter::schema::vault_model_t::segregated,
                                        .label = std::nullopt})));
    txs.push_back(encode_tx(make_tx(
        chain_id, 3, signer,
        charter::schema::upsert_destination_t{
            .workspace_id = workspace_id,
            .destination_id = destination_id,
            .type = charter::schema::destination_type_t::address,
            .chain_type = charter::schema::chain_type_t{
                charter::schema::chain_type::ethereum},
            .address_or_contract = charter::schema::bytes_t{0x01, 0x02},
            .enabled = true,
            .label = std::nullopt})));
    txs.push_back(encode_tx(make_tx(
        chain_id, 4, signer,
        charter::schema::create_policy_set_t{
            .policy_set_id = policy_set_id,
            .scope = scope,
            .policy_version = 1,
            .roles = {{charter::schema::role_id_t::approver, {signer}}},
            .rules = {make_transfer_rule(asset_id, 1, 3000)}})));
    txs.push_back(encode_tx(make_tx(
        chain_id, 5, signer,
        charter::schema::activate_policy_set_t{
            .scope = scope, .policy_set_id = policy_set_id, .policy_set_version = 1})));
    txs.push_back(encode_tx(make_tx(
        chain_id, 6, signer,
        charter::schema::propose_intent_t{
            .workspace_id = workspace_id,
            .vault_id = vault_id,
            .intent_id = intent_id,
            .action = charter::schema::transfer_parameters_t{
                .asset_id = asset_id,
                .destination_id = destination_id,
                .amount = 5},
            .expires_at = std::nullopt})));
    txs.push_back(encode_tx(make_tx(
        chain_id, 7, signer,
        charter::schema::approve_intent_t{
            .workspace_id = workspace_id, .vault_id = vault_id, .intent_id = intent_id})));
    txs.push_back(encode_tx(make_tx(
        chain_id, 8, signer,
        charter::schema::execute_intent_t{
            .workspace_id = workspace_id, .vault_id = vault_id, .intent_id = intent_id})));

    auto block1 = engine.finalize_block(1, txs);
    ASSERT_EQ(block1.tx_results.size(), txs.size());
    EXPECT_EQ(block1.tx_results[7].code, 26u);
    engine.commit();

    auto tx8 = encode_tx(make_tx(
        chain_id, 8, signer,
        charter::schema::execute_intent_t{
            .workspace_id = workspace_id, .vault_id = vault_id, .intent_id = intent_id}));
    auto block4 = engine.finalize_block(4, {tx8});
    ASSERT_EQ(block4.tx_results.size(), 1u);
    EXPECT_EQ(block4.tx_results[0].code, 0u);
    engine.commit();

    auto encoder = encoder_t{};
    auto intent_key = encoder.encode(std::tuple{workspace_id, vault_id, intent_id});
    auto intent_query = engine.query(
        "/state/intent", charter::schema::bytes_view_t{intent_key.data(), intent_key.size()});
    ASSERT_EQ(intent_query.code, 0u);
    auto intent = encoder.decode<charter::schema::intent_state_t>(
        charter::schema::bytes_view_t{intent_query.value.data(), intent_query.value.size()});
    EXPECT_EQ(intent.status, charter::schema::intent_status_t::executed);
  }

  std::error_code ec;
  std::filesystem::remove_all(db, ec);
}

TEST(engine_integration, limit_and_whitelist_are_enforced) {
  auto db = make_db_path("charter_engine_limits");

  auto signer = make_named_signer(31);
  auto workspace_id = make_hash(21);
  auto vault_id = make_hash(22);
  auto policy_set_id = make_hash(23);
  auto asset_id = make_hash(24);
  auto destination_id = make_hash(25);

  auto scope = charter::schema::policy_scope_t{
      charter::schema::vault_t{.workspace_id = workspace_id, .vault_id = vault_id}};

  {
    auto engine = charter::execution::engine{1, db, false};
    engine.set_signature_verifier([](const charter::schema::bytes_view_t &,
                                     const charter::schema::signer_id_t &,
                                     const charter::schema::signature_t &) {
      return true;
    });
    auto chain_id = chain_id_from_engine(engine);

    auto block1 = engine.finalize_block(
        1,
        {encode_tx(make_tx(chain_id, 1, signer,
                           charter::schema::create_workspace_t{
                               .workspace_id = workspace_id,
                               .admin_set = {signer},
                               .quorum_size = 1,
                               .metadata_ref = std::nullopt})),
         encode_tx(make_tx(chain_id, 2, signer,
                           charter::schema::create_vault_t{
                               .workspace_id = workspace_id,
                               .vault_id = vault_id,
                               .model = charter::schema::vault_model_t::segregated,
                               .label = std::nullopt})),
         encode_tx(make_tx(chain_id, 3, signer,
                           charter::schema::upsert_destination_t{
                               .workspace_id = workspace_id,
                               .destination_id = destination_id,
                               .type = charter::schema::destination_type_t::address,
                               .chain_type = charter::schema::chain_type_t{
                                   charter::schema::chain_type::ethereum},
                               .address_or_contract =
                                   charter::schema::bytes_t{0x11, 0x22},
                               .enabled = false,
                               .label = std::nullopt})),
         encode_tx(make_tx(chain_id, 4, signer,
                           charter::schema::create_policy_set_t{
                               .policy_set_id = policy_set_id,
                               .scope = scope,
                               .policy_version = 1,
                               .roles = {{charter::schema::role_id_t::approver, {signer}}},
                               .rules = {make_transfer_rule(
                                   asset_id, 1, 0, 10, true)}})),
         encode_tx(make_tx(chain_id, 5, signer,
                           charter::schema::activate_policy_set_t{
                               .scope = scope,
                               .policy_set_id = policy_set_id,
                               .policy_set_version = 1}))});
    for (const auto &tx_result : block1.tx_results) {
      EXPECT_EQ(tx_result.code, 0u);
    }
    engine.commit();

    auto block2 = engine.finalize_block(
        2,
        {encode_tx(make_tx(chain_id, 6, signer,
                           charter::schema::propose_intent_t{
                               .workspace_id = workspace_id,
                               .vault_id = vault_id,
                               .intent_id = make_hash(26),
                               .action = charter::schema::transfer_parameters_t{
                                   .asset_id = asset_id,
                                   .destination_id = destination_id,
                                   .amount = 11},
                               .expires_at = std::nullopt}))});
    ASSERT_EQ(block2.tx_results.size(), 1u);
    EXPECT_EQ(block2.tx_results[0].code, 28u);
    engine.commit();

    auto block3 = engine.finalize_block(
        3,
        {encode_tx(make_tx(chain_id, 6, signer,
                           charter::schema::propose_intent_t{
                               .workspace_id = workspace_id,
                               .vault_id = vault_id,
                               .intent_id = make_hash(27),
                               .action = charter::schema::transfer_parameters_t{
                                   .asset_id = asset_id,
                                   .destination_id = destination_id,
                                   .amount = 5},
                               .expires_at = std::nullopt}))});
    ASSERT_EQ(block3.tx_results.size(), 1u);
    EXPECT_EQ(block3.tx_results[0].code, 29u);
    engine.commit();

    auto block4 = engine.finalize_block(
        4,
        {encode_tx(make_tx(chain_id, 6, signer,
                           charter::schema::upsert_destination_t{
                               .workspace_id = workspace_id,
                               .destination_id = destination_id,
                               .type = charter::schema::destination_type_t::address,
                               .chain_type = charter::schema::chain_type_t{
                                   charter::schema::chain_type::ethereum},
                               .address_or_contract =
                                   charter::schema::bytes_t{0x11, 0x22},
                               .enabled = true,
                               .label = std::nullopt}))});
    ASSERT_EQ(block4.tx_results.size(), 1u);
    EXPECT_EQ(block4.tx_results[0].code, 0u);
    engine.commit();

    auto block5 = engine.finalize_block(
        5,
        {encode_tx(make_tx(chain_id, 7, signer,
                           charter::schema::propose_intent_t{
                               .workspace_id = workspace_id,
                               .vault_id = vault_id,
                               .intent_id = make_hash(28),
                               .action = charter::schema::transfer_parameters_t{
                                   .asset_id = asset_id,
                                   .destination_id = destination_id,
                                   .amount = 5},
                               .expires_at = std::nullopt}))});
    ASSERT_EQ(block5.tx_results.size(), 1u);
    EXPECT_EQ(block5.tx_results[0].code, 0u);
  }

  std::error_code ec;
  std::filesystem::remove_all(db, ec);
}

TEST(engine_integration, claim_gating_blocks_until_attested) {
  auto db = make_db_path("charter_engine_claims");

  auto signer = make_named_signer(41);
  auto workspace_id = make_hash(31);
  auto vault_id = make_hash(32);
  auto policy_set_id = make_hash(33);
  auto asset_id = make_hash(34);
  auto destination_id = make_hash(35);
  auto intent_id = make_hash(36);

  auto scope = charter::schema::policy_scope_t{
      charter::schema::vault_t{.workspace_id = workspace_id, .vault_id = vault_id}};

  {
    auto engine = charter::execution::engine{1, db, false};
    engine.set_signature_verifier([](const charter::schema::bytes_view_t &,
                                     const charter::schema::signer_id_t &,
                                     const charter::schema::signature_t &) {
      return true;
    });
    auto chain_id = chain_id_from_engine(engine);

    auto setup = engine.finalize_block(
        1,
        {encode_tx(make_tx(chain_id, 1, signer,
                           charter::schema::create_workspace_t{
                               .workspace_id = workspace_id,
                               .admin_set = {signer},
                               .quorum_size = 1,
                               .metadata_ref = std::nullopt})),
         encode_tx(make_tx(chain_id, 2, signer,
                           charter::schema::create_vault_t{
                               .workspace_id = workspace_id,
                               .vault_id = vault_id,
                               .model = charter::schema::vault_model_t::segregated,
                               .label = std::nullopt})),
         encode_tx(make_tx(chain_id, 3, signer,
                           charter::schema::upsert_destination_t{
                               .workspace_id = workspace_id,
                               .destination_id = destination_id,
                               .type = charter::schema::destination_type_t::address,
                               .chain_type = charter::schema::chain_type_t{
                                   charter::schema::chain_type::ethereum},
                               .address_or_contract =
                                   charter::schema::bytes_t{0xAA, 0xBB},
                               .enabled = true,
                               .label = std::nullopt})),
         encode_tx(make_tx(chain_id, 4, signer,
                           charter::schema::create_policy_set_t{
                               .policy_set_id = policy_set_id,
                               .scope = scope,
                               .policy_version = 1,
                               .roles = {{charter::schema::role_id_t::approver, {signer}}},
                               .rules = {make_transfer_rule(
                                   asset_id, 1, 0, std::nullopt, false,
                                   {charter::schema::claim_type_t{
                                       charter::schema::claim_type::kyb_verified}})}})),
         encode_tx(make_tx(chain_id, 5, signer,
                           charter::schema::activate_policy_set_t{
                               .scope = scope,
                               .policy_set_id = policy_set_id,
                               .policy_set_version = 1}))});
    for (const auto &tx_result : setup.tx_results) {
      EXPECT_EQ(tx_result.code, 0u);
    }
    engine.commit();

    auto block2 = engine.finalize_block(
        2,
        {encode_tx(make_tx(chain_id, 6, signer,
                           charter::schema::propose_intent_t{
                               .workspace_id = workspace_id,
                               .vault_id = vault_id,
                               .intent_id = intent_id,
                               .action = charter::schema::transfer_parameters_t{
                                   .asset_id = asset_id,
                                   .destination_id = destination_id,
                                   .amount = 3},
                               .expires_at = std::nullopt})),
         encode_tx(make_tx(chain_id, 7, signer,
                           charter::schema::approve_intent_t{
                               .workspace_id = workspace_id,
                               .vault_id = vault_id,
                               .intent_id = intent_id})),
         encode_tx(make_tx(chain_id, 8, signer,
                           charter::schema::execute_intent_t{
                               .workspace_id = workspace_id,
                               .vault_id = vault_id,
                               .intent_id = intent_id}))});
    ASSERT_EQ(block2.tx_results.size(), 3u);
    EXPECT_EQ(block2.tx_results[0].code, 0u);
    EXPECT_EQ(block2.tx_results[1].code, 0u);
    EXPECT_EQ(block2.tx_results[2].code, 30u);
    engine.commit();

    auto block3 = engine.finalize_block(
        3,
        {encode_tx(make_tx(chain_id, 8, signer,
                           charter::schema::upsert_attestation_t{
                               .workspace_id = workspace_id,
                               .subject = workspace_id,
                               .claim = charter::schema::claim_type_t{
                                   charter::schema::claim_type::kyb_verified},
                               .issuer = signer,
                               .expires_at = 99999999,
                               .reference_hash = std::nullopt})),
         encode_tx(make_tx(chain_id, 9, signer,
                           charter::schema::execute_intent_t{
                               .workspace_id = workspace_id,
                               .vault_id = vault_id,
                               .intent_id = intent_id}))});
    ASSERT_EQ(block3.tx_results.size(), 2u);
    EXPECT_EQ(block3.tx_results[0].code, 0u);
    EXPECT_EQ(block3.tx_results[1].code, 0u);
  }

  std::error_code ec;
  std::filesystem::remove_all(db, ec);
}

TEST(engine_integration, query_errors_echo_key_and_codespace) {
  auto db = make_db_path("charter_engine_query_contract");
  {
    auto engine = charter::execution::engine{1, db, false};
    auto keyspaces = engine.query("/engine/keyspaces", {});
    ASSERT_EQ(keyspaces.code, 0u);
    auto encoder = encoder_t{};
    auto prefixes = encoder.decode<std::vector<std::string>>(
        charter::schema::bytes_view_t{keyspaces.value.data(), keyspaces.value.size()});
    EXPECT_FALSE(prefixes.empty());
    EXPECT_TRUE(std::find(std::begin(prefixes), std::end(prefixes),
                          "SYS|STATE|WORKSPACE|") != std::end(prefixes));

    auto bad_key = charter::schema::bytes_t{0xAA, 0xBB, 0xCC};
    auto result = engine.query(
        "/state/workspace",
        charter::schema::bytes_view_t{bad_key.data(), bad_key.size()});
    EXPECT_EQ(result.code, 1u);
    EXPECT_EQ(result.codespace, "charter.query");
    EXPECT_EQ(result.key, bad_key);
    EXPECT_EQ(result.height, engine.info().last_block_height);
  }
  std::error_code ec;
  std::filesystem::remove_all(db, ec);
}

TEST(engine_integration, deterministic_history_export_matches_across_nodes) {
  auto db1 = make_db_path("charter_engine_determinism_1");
  auto db2 = make_db_path("charter_engine_determinism_2");

  auto signer = make_named_signer(51);
  auto workspace_id = make_hash(61);
  auto vault_id = make_hash(62);
  auto policy_set_id = make_hash(63);
  auto asset_id = make_hash(64);
  auto destination_id = make_hash(65);
  auto scope = charter::schema::policy_scope_t{
      charter::schema::vault_t{.workspace_id = workspace_id, .vault_id = vault_id}};

  auto run_sequence = [&](const std::string& db_path) {
    auto engine = charter::execution::engine{1, db_path, false};
    engine.set_signature_verifier([](const charter::schema::bytes_view_t &,
                                     const charter::schema::signer_id_t &,
                                     const charter::schema::signature_t &) {
      return true;
    });
    auto chain_id = chain_id_from_engine(engine);
    auto block = engine.finalize_block(
        1,
        {encode_tx(make_tx(chain_id, 1, signer,
                           charter::schema::create_workspace_t{
                               .workspace_id = workspace_id,
                               .admin_set = {signer},
                               .quorum_size = 1,
                               .metadata_ref = std::nullopt})),
         encode_tx(make_tx(chain_id, 2, signer,
                           charter::schema::create_vault_t{
                               .workspace_id = workspace_id,
                               .vault_id = vault_id,
                               .model = charter::schema::vault_model_t::segregated,
                               .label = std::nullopt})),
         encode_tx(make_tx(chain_id, 3, signer,
                           charter::schema::upsert_destination_t{
                               .workspace_id = workspace_id,
                               .destination_id = destination_id,
                               .type = charter::schema::destination_type_t::address,
                               .chain_type = charter::schema::chain_type_t{
                                   charter::schema::chain_type::ethereum},
                               .address_or_contract = charter::schema::bytes_t{0x33, 0x44},
                               .enabled = true,
                               .label = std::nullopt})),
         encode_tx(make_tx(chain_id, 4, signer,
                           charter::schema::create_policy_set_t{
                               .policy_set_id = policy_set_id,
                               .scope = scope,
                               .policy_version = 1,
                               .roles = {{charter::schema::role_id_t::approver, {signer}}},
                               .rules = {make_transfer_rule(asset_id, 1, 0)}})),
         encode_tx(make_tx(chain_id, 5, signer,
                           charter::schema::activate_policy_set_t{
                               .scope = scope,
                               .policy_set_id = policy_set_id,
                               .policy_set_version = 1}))});
    for (const auto& tx_result : block.tx_results) {
      EXPECT_EQ(tx_result.code, 0u);
    }
    engine.commit();
    auto exported = engine.query("/history/export", {});
    EXPECT_EQ(exported.code, 0u);
    return std::tuple{engine.export_backup(), exported.value, engine.info().last_block_app_hash};
  };

  auto [backup1, export1, app_hash1] = run_sequence(db1);
  auto [backup2, export2, app_hash2] = run_sequence(db2);

  EXPECT_FALSE(export1.empty());
  EXPECT_FALSE(export2.empty());
  EXPECT_FALSE(backup1.empty());
  EXPECT_FALSE(backup2.empty());

  auto restored_db = make_db_path("charter_engine_determinism_restore");
  auto restored = charter::execution::engine{1, restored_db, false};
  restored.set_signature_verifier([](const charter::schema::bytes_view_t &,
                                     const charter::schema::signer_id_t &,
                                     const charter::schema::signature_t &) {
    return true;
  });
  auto error = std::string{};
  EXPECT_TRUE(restored.import_backup(
      charter::schema::bytes_view_t{backup1.data(), backup1.size()}, error));
  auto replay = restored.replay_history();
  EXPECT_TRUE(replay.ok);
  auto restored_export = restored.query("/history/export", {});
  EXPECT_EQ(restored_export.code, 0u);
  EXPECT_FALSE(restored_export.value.empty());

  std::error_code ec;
  std::filesystem::remove_all(db1, ec);
  std::filesystem::remove_all(db2, ec);
  std::filesystem::remove_all(restored_db, ec);
}

TEST(engine_integration, replay_history_is_idempotent_for_same_chain_state) {
  auto db = make_db_path("charter_engine_replay_idempotent");
  {
    auto engine = charter::execution::engine{1, db, false};
    engine.set_signature_verifier([](const charter::schema::bytes_view_t&,
                                     const charter::schema::signer_id_t&,
                                     const charter::schema::signature_t&) {
      return true;
    });
    auto chain_id = chain_id_from_engine(engine);
    auto signer = make_named_signer(91);
    auto workspace = make_hash(92);

    auto block = engine.finalize_block(
        1, {encode_tx(make_tx(chain_id, 1, signer,
                              charter::schema::create_workspace_t{
                                  .workspace_id = workspace,
                                  .admin_set = {signer},
                                  .quorum_size = 1,
                                  .metadata_ref = std::nullopt}))});
    ASSERT_EQ(block.tx_results.size(), 1u);
    EXPECT_EQ(block.tx_results[0].code, 0u);
    (void)engine.commit();

    auto replay1 = engine.replay_history();
    auto replay2 = engine.replay_history();
    EXPECT_TRUE(replay1.ok);
    EXPECT_TRUE(replay2.ok);
    EXPECT_EQ(replay1.tx_count, replay2.tx_count);
    EXPECT_EQ(replay1.applied_count, replay2.applied_count);
    EXPECT_EQ(replay1.last_height, replay2.last_height);
    EXPECT_EQ(replay1.app_hash, replay2.app_hash);
    EXPECT_EQ(engine.info().last_block_height, replay2.last_height);
  }

  std::error_code ec;
  std::filesystem::remove_all(db, ec);
}

TEST(engine_integration, snapshot_chunk_corruption_is_rejected_then_recovers) {
  auto db = make_db_path("charter_engine_snapshot_corrupt");
  {
    auto engine = charter::execution::engine{1, db, false};
    engine.set_signature_verifier([](const charter::schema::bytes_view_t&,
                                     const charter::schema::signer_id_t&,
                                     const charter::schema::signature_t&) {
      return true;
    });
    auto chain_id = chain_id_from_engine(engine);
    auto signer = make_named_signer(101);
    auto workspace = make_hash(102);

    auto block = engine.finalize_block(
        1, {encode_tx(make_tx(chain_id, 1, signer,
                              charter::schema::create_workspace_t{
                                  .workspace_id = workspace,
                                  .admin_set = {signer},
                                  .quorum_size = 1,
                                  .metadata_ref = std::nullopt}))});
    ASSERT_EQ(block.tx_results.size(), 1u);
    EXPECT_EQ(block.tx_results[0].code, 0u);
    (void)engine.commit();

    auto snapshots = engine.list_snapshots();
    ASSERT_FALSE(snapshots.empty());
    auto offered = snapshots.front();
    EXPECT_EQ(engine.offer_snapshot(offered, offered.hash),
              charter::execution::offer_snapshot_result::accept);

    auto chunk = engine.load_snapshot_chunk(offered.height, offered.format, 0);
    ASSERT_TRUE(chunk.has_value());
    ASSERT_FALSE(chunk->empty());

    auto corrupted = *chunk;
    corrupted[0] ^= 0xFF;
    auto corrupted_result = engine.apply_snapshot_chunk(
        0, charter::schema::bytes_view_t{corrupted.data(), corrupted.size()},
        "peer-a");
    EXPECT_EQ(corrupted_result,
              charter::execution::apply_snapshot_chunk_result::reject_snapshot);

    auto wrong_index = engine.apply_snapshot_chunk(
        1, charter::schema::bytes_view_t{chunk->data(), chunk->size()},
        "peer-a");
    EXPECT_EQ(wrong_index,
              charter::execution::apply_snapshot_chunk_result::retry_snapshot);

    EXPECT_EQ(engine.offer_snapshot(offered, offered.hash),
              charter::execution::offer_snapshot_result::accept);
    auto applied_result = engine.apply_snapshot_chunk(
        0, charter::schema::bytes_view_t{chunk->data(), chunk->size()},
        "peer-a");
    EXPECT_EQ(applied_result,
              charter::execution::apply_snapshot_chunk_result::accept);
  }

  std::error_code ec;
  std::filesystem::remove_all(db, ec);
}

TEST(engine_integration, tx_error_code_matrix_coverage) {
  auto observed = std::set<uint32_t>{};
  auto run = [&](const std::string& label, const auto& fn) {
    auto db = make_db_path("charter_engine_code_" + label);
    {
      auto engine = charter::execution::engine{1, db, false};
      engine.set_signature_verifier([](const charter::schema::bytes_view_t &,
                                       const charter::schema::signer_id_t &,
                                       const charter::schema::signature_t &) {
        return true;
      });
      fn(engine, observed);
    }
    std::error_code ec;
    std::filesystem::remove_all(db, ec);
  };

  run("1", [](auto& engine, auto& seen) {
    auto result = engine.check_tx(charter::schema::bytes_view_t{
        reinterpret_cast<const uint8_t*>("\xFF"), 1});
    seen.insert(result.code);
    EXPECT_EQ(result.code, 1u);
  });

  run("2", [](auto& engine, auto& seen) {
    auto chain = chain_id_from_engine(engine);
    auto signer = make_named_signer(1);
    auto tx = make_tx(chain, 1, signer, charter::schema::create_workspace_t{
        .workspace_id = make_hash(10), .admin_set = {signer}, .quorum_size = 1,
        .metadata_ref = std::nullopt});
    tx.version = 2;
    auto raw = encode_tx(tx);
    auto result = engine.check_tx(
        charter::schema::bytes_view_t{raw.data(), raw.size()});
    seen.insert(result.code);
    EXPECT_EQ(result.code, 2u);
  });

  run("3", [](auto& engine, auto& seen) {
    auto chain = chain_id_from_engine(engine);
    auto signer = make_named_signer(2);
    auto bad_chain = chain;
    bad_chain[0] ^= 0xAA;
    auto tx = make_tx(bad_chain, 1, signer, charter::schema::create_workspace_t{
        .workspace_id = make_hash(11), .admin_set = {signer}, .quorum_size = 1,
        .metadata_ref = std::nullopt});
    auto raw = encode_tx(tx);
    auto result = engine.check_tx(charter::schema::bytes_view_t{raw.data(), raw.size()});
    seen.insert(result.code);
    EXPECT_EQ(result.code, 3u);
  });

  run("4", [](auto& engine, auto& seen) {
    auto chain = chain_id_from_engine(engine);
    auto signer = make_named_signer(3);
    auto tx = make_tx(chain, 2, signer, charter::schema::create_workspace_t{
        .workspace_id = make_hash(12), .admin_set = {signer}, .quorum_size = 1,
        .metadata_ref = std::nullopt});
    auto raw = encode_tx(tx);
    auto result = engine.check_tx(charter::schema::bytes_view_t{raw.data(), raw.size()});
    seen.insert(result.code);
    EXPECT_EQ(result.code, 4u);
  });

  run("5", [](auto& engine, auto& seen) {
    auto chain = chain_id_from_engine(engine);
    auto signer_key = charter::schema::ed25519_signer_id{};
    signer_key.public_key[0] = 1;
    auto tx = make_tx(chain, 1, charter::schema::signer_id_t{signer_key},
                      charter::schema::create_workspace_t{
                          .workspace_id = make_hash(13),
                          .admin_set = {charter::schema::signer_id_t{signer_key}},
                          .quorum_size = 1,
                          .metadata_ref = std::nullopt});
    tx.signature = charter::schema::secp256k1_signature_t{};
    auto raw = encode_tx(tx);
    auto result = engine.check_tx(charter::schema::bytes_view_t{raw.data(), raw.size()});
    seen.insert(result.code);
    EXPECT_EQ(result.code, 5u);
  });

  run("6", [](auto& engine, auto& seen) {
    engine.set_signature_verifier([](const charter::schema::bytes_view_t &,
                                     const charter::schema::signer_id_t &,
                                     const charter::schema::signature_t &) {
      return false;
    });
    auto chain = chain_id_from_engine(engine);
    auto signer = make_named_signer(4);
    auto tx = make_tx(chain, 1, signer, charter::schema::create_workspace_t{
        .workspace_id = make_hash(14), .admin_set = {signer}, .quorum_size = 1,
        .metadata_ref = std::nullopt});
    auto raw = encode_tx(tx);
    auto result = engine.check_tx(charter::schema::bytes_view_t{raw.data(), raw.size()});
    seen.insert(result.code);
    EXPECT_EQ(result.code, 6u);
  });

  run("10_12_14_19_24_37", [](auto& engine, auto& seen) {
    auto chain = chain_id_from_engine(engine);
    auto signer = make_named_signer(10);
    auto workspace_id = make_hash(20);
    auto vault_id = make_hash(21);
    auto policy_set_id = make_hash(22);
    auto destination_id = make_hash(23);
    auto intent_id = make_hash(24);
    auto scope = charter::schema::policy_scope_t{
        charter::schema::vault_t{.workspace_id = workspace_id, .vault_id = vault_id}};

    EXPECT_EQ(finalize_single(engine, 1,
                              make_tx(chain, 1, signer,
                                      charter::schema::create_workspace_t{
                                          .workspace_id = workspace_id,
                                          .admin_set = {signer},
                                          .quorum_size = 1,
                                          .metadata_ref = std::nullopt}))
                  .code,
              0u);
    auto dup_workspace = finalize_single(
        engine, 2,
        make_tx(chain, 2, signer,
                charter::schema::create_workspace_t{
                    .workspace_id = workspace_id,
                    .admin_set = {signer},
                    .quorum_size = 1,
                    .metadata_ref = std::nullopt}));
    seen.insert(dup_workspace.code);
    EXPECT_EQ(dup_workspace.code, 10u);

    EXPECT_EQ(finalize_single(engine, 3,
                              make_tx(chain, 3, signer,
                                      charter::schema::create_vault_t{
                                          .workspace_id = workspace_id,
                                          .vault_id = vault_id,
                                          .model = charter::schema::vault_model_t::segregated,
                                          .label = std::nullopt}))
                  .code,
              0u);
    auto dup_vault = finalize_single(
        engine, 4,
        make_tx(chain, 4, signer,
                charter::schema::create_vault_t{
                    .workspace_id = workspace_id,
                    .vault_id = vault_id,
                    .model = charter::schema::vault_model_t::segregated,
                    .label = std::nullopt}));
    seen.insert(dup_vault.code);
    EXPECT_EQ(dup_vault.code, 12u);

    EXPECT_EQ(finalize_single(engine, 5,
                              make_tx(chain, 5, signer,
                                      charter::schema::create_policy_set_t{
                                          .policy_set_id = policy_set_id,
                                          .scope = scope,
                                          .policy_version = 1,
                                          .roles = {{charter::schema::role_id_t::approver, {signer}}},
                                          .rules = {make_transfer_rule(make_hash(25), 1, 0)}}))
                  .code,
              0u);
    auto dup_policy = finalize_single(
        engine, 6,
        make_tx(chain, 6, signer,
                charter::schema::create_policy_set_t{
                    .policy_set_id = policy_set_id,
                    .scope = scope,
                    .policy_version = 1,
                    .roles = {{charter::schema::role_id_t::approver, {signer}}},
                    .rules = {make_transfer_rule(make_hash(25), 1, 0)}}));
    seen.insert(dup_policy.code);
    EXPECT_EQ(dup_policy.code, 14u);

    EXPECT_EQ(finalize_single(engine, 7,
                              make_tx(chain, 7, signer,
                                      charter::schema::upsert_destination_t{
                                          .workspace_id = workspace_id,
                                          .destination_id = destination_id,
                                          .type = charter::schema::destination_type_t::address,
                                          .chain_type = charter::schema::chain_type_t{
                                              charter::schema::chain_type::ethereum},
                                          .address_or_contract = charter::schema::bytes_t{1},
                                          .enabled = true,
                                          .label = std::nullopt}))
                  .code,
              0u);
    EXPECT_EQ(finalize_single(engine, 8,
                              make_tx(chain, 8, signer,
                                      charter::schema::activate_policy_set_t{
                                          .scope = scope,
                                          .policy_set_id = policy_set_id,
                                          .policy_set_version = 1}))
                  .code,
              0u);
    EXPECT_EQ(finalize_single(engine, 9,
                              make_tx(chain, 9, signer,
                                      charter::schema::propose_intent_t{
                                          .workspace_id = workspace_id,
                                          .vault_id = vault_id,
                                          .intent_id = intent_id,
                                          .action = charter::schema::transfer_parameters_t{
                                              .asset_id = make_hash(25),
                                              .destination_id = destination_id,
                                              .amount = 3},
                                          .expires_at = std::nullopt}))
                  .code,
              0u);
    auto dup_intent = finalize_single(
        engine, 10,
        make_tx(chain, 10, signer,
                charter::schema::propose_intent_t{
                    .workspace_id = workspace_id,
                    .vault_id = vault_id,
                    .intent_id = intent_id,
                    .action = charter::schema::transfer_parameters_t{
                        .asset_id = make_hash(25),
                        .destination_id = destination_id,
                        .amount = 3},
                    .expires_at = std::nullopt}));
    seen.insert(dup_intent.code);
    EXPECT_EQ(dup_intent.code, 19u);

    EXPECT_EQ(finalize_single(engine, 11,
                              make_tx(chain, 11, signer,
                                      charter::schema::approve_intent_t{
                                          .workspace_id = workspace_id,
                                          .vault_id = vault_id,
                                          .intent_id = intent_id}))
                  .code,
              0u);
    auto dup_approval = finalize_single(
        engine, 12,
        make_tx(chain, 12, signer,
                charter::schema::approve_intent_t{
                    .workspace_id = workspace_id,
                    .vault_id = vault_id,
                    .intent_id = intent_id}));
    seen.insert(dup_approval.code);
    EXPECT_EQ(dup_approval.code, 24u);

    auto missing_update = finalize_single(
        engine, 13,
        make_tx(chain, 13, signer,
                charter::schema::approve_destination_update_t{
                    .workspace_id = workspace_id,
                    .destination_id = destination_id,
                    .update_id = make_hash(26)}));
    seen.insert(missing_update.code);
    EXPECT_EQ(missing_update.code, 37u);
  });

  run("11_13_15_16_17_18_21_27_36_38_39", [](auto& engine, auto& seen) {
    auto chain = chain_id_from_engine(engine);
    auto signer = make_named_signer(20);
    auto ws = make_hash(30);
    auto vault = make_hash(31);
    auto policy = make_hash(32);
    auto dst = make_hash(33);
    auto update = make_hash(34);

    auto missing_ws_vault = finalize_single(
        engine, 1,
        make_tx(chain, 1, signer,
                charter::schema::create_vault_t{
                    .workspace_id = ws,
                    .vault_id = vault,
                    .model = charter::schema::vault_model_t::segregated,
                    .label = std::nullopt}));
    seen.insert(missing_ws_vault.code);
    EXPECT_EQ(missing_ws_vault.code, 11u);

    auto missing_scope_policy = finalize_single(
        engine, 2,
        make_tx(chain, 2, signer,
                charter::schema::create_policy_set_t{
                    .policy_set_id = policy,
                    .scope = charter::schema::policy_scope_t{
                        charter::schema::vault_t{.workspace_id = ws, .vault_id = vault}},
                    .policy_version = 1,
                    .roles = {},
                    .rules = {}}));
    seen.insert(missing_scope_policy.code);
    EXPECT_EQ(missing_scope_policy.code, 13u);

    EXPECT_EQ(finalize_single(engine, 3,
                              make_tx(chain, 3, signer,
                                      charter::schema::create_workspace_t{
                                          .workspace_id = ws,
                                          .admin_set = {signer},
                                          .quorum_size = 1,
                                          .metadata_ref = std::nullopt}))
                  .code,
              0u);

    auto missing_policy = finalize_single(
        engine, 4,
        make_tx(chain, 4, signer,
                charter::schema::activate_policy_set_t{
                    .scope = charter::schema::policy_scope_t{
                        charter::schema::workspace_scope_t{.workspace_id = ws}},
                    .policy_set_id = policy,
                    .policy_set_version = 1}));
    seen.insert(missing_policy.code);
    EXPECT_EQ(missing_policy.code, 15u);

    auto missing_vault_scope = finalize_single(
        engine, 5,
        make_tx(chain, 5, signer,
                charter::schema::propose_intent_t{
                    .workspace_id = ws,
                    .vault_id = vault,
                    .intent_id = make_hash(35),
                    .action = charter::schema::transfer_parameters_t{
                        .asset_id = make_hash(36),
                        .destination_id = dst,
                        .amount = 1},
                    .expires_at = std::nullopt}));
    seen.insert(missing_vault_scope.code);
    EXPECT_EQ(missing_vault_scope.code, 16u);

    EXPECT_EQ(finalize_single(engine, 6,
                              make_tx(chain, 6, signer,
                                      charter::schema::create_vault_t{
                                          .workspace_id = ws,
                                          .vault_id = vault,
                                          .model = charter::schema::vault_model_t::segregated,
                                          .label = std::nullopt}))
                  .code,
              0u);
    auto no_active = finalize_single(
        engine, 7,
        make_tx(chain, 7, signer,
                charter::schema::propose_intent_t{
                    .workspace_id = ws,
                    .vault_id = vault,
                    .intent_id = make_hash(37),
                    .action = charter::schema::transfer_parameters_t{
                        .asset_id = make_hash(36),
                        .destination_id = dst,
                        .amount = 1},
                    .expires_at = std::nullopt}));
    seen.insert(no_active.code);
    EXPECT_EQ(no_active.code, 17u);

    auto missing_ws_attestation = finalize_single(
        engine, 8,
        make_tx(chain, 8, signer,
                charter::schema::upsert_attestation_t{
                    .workspace_id = make_hash(99),
                    .subject = ws,
                    .claim = charter::schema::claim_type_t{
                        charter::schema::claim_type::kyb_verified},
                    .issuer = signer,
                    .expires_at = 9999999,
                    .reference_hash = std::nullopt}));
    seen.insert(missing_ws_attestation.code);
    EXPECT_EQ(missing_ws_attestation.code, 18u);

    auto missing_intent = finalize_single(
        engine, 9,
        make_tx(chain, 9, signer,
                charter::schema::approve_intent_t{
                    .workspace_id = ws,
                    .vault_id = vault,
                    .intent_id = make_hash(38)}));
    seen.insert(missing_intent.code);
    EXPECT_EQ(missing_intent.code, 21u);

    auto missing_attestation = finalize_single(
        engine, 10,
        make_tx(chain, 10, signer,
                charter::schema::revoke_attestation_t{
                    .workspace_id = ws,
                    .subject = ws,
                    .claim = charter::schema::claim_type_t{
                        charter::schema::claim_type::kyb_verified},
                    .issuer = signer}));
    seen.insert(missing_attestation.code);
    EXPECT_EQ(missing_attestation.code, 27u);

    auto first_update = finalize_single(
        engine, 11,
        make_tx(chain, 11, signer,
                charter::schema::propose_destination_update_t{
                    .workspace_id = ws,
                    .destination_id = dst,
                    .update_id = update,
                    .type = charter::schema::destination_type_t::address,
                    .chain_type = charter::schema::chain_type_t{
                        charter::schema::chain_type::ethereum},
                    .address_or_contract = charter::schema::bytes_t{0x11},
                    .enabled = true,
                    .label = std::nullopt,
                    .required_approvals = 1,
                    .delay_ms = 0}));
    EXPECT_EQ(first_update.code, 0u);
    auto dup_update = finalize_single(
        engine, 12,
        make_tx(chain, 12, signer,
                charter::schema::propose_destination_update_t{
                    .workspace_id = ws,
                    .destination_id = dst,
                    .update_id = update,
                    .type = charter::schema::destination_type_t::address,
                    .chain_type = charter::schema::chain_type_t{
                        charter::schema::chain_type::ethereum},
                    .address_or_contract = charter::schema::bytes_t{0x11},
                    .enabled = true,
                    .label = std::nullopt,
                    .required_approvals = 1,
                    .delay_ms = 0}));
    seen.insert(dup_update.code);
    EXPECT_EQ(dup_update.code, 36u);

    EXPECT_EQ(finalize_single(engine, 13,
                              make_tx(chain, 13, signer,
                                      charter::schema::approve_destination_update_t{
                                          .workspace_id = ws,
                                          .destination_id = dst,
                                          .update_id = update}))
                  .code,
              0u);
    EXPECT_EQ(finalize_single(engine, 14,
                              make_tx(chain, 14, signer,
                                      charter::schema::apply_destination_update_t{
                                          .workspace_id = ws,
                                          .destination_id = dst,
                                          .update_id = update}))
                  .code,
              0u);
    auto finalized_update = finalize_single(
        engine, 15,
        make_tx(chain, 15, signer,
                charter::schema::approve_destination_update_t{
                    .workspace_id = ws,
                    .destination_id = dst,
                    .update_id = update}));
    seen.insert(finalized_update.code);
    EXPECT_EQ(finalized_update.code, 38u);

    auto update2 = make_hash(39);
    EXPECT_EQ(finalize_single(engine, 16,
                              make_tx(chain, 16, signer,
                                      charter::schema::propose_destination_update_t{
                                          .workspace_id = ws,
                                          .destination_id = dst,
                                          .update_id = update2,
                                          .type = charter::schema::destination_type_t::address,
                                          .chain_type = charter::schema::chain_type_t{
                                              charter::schema::chain_type::ethereum},
                                          .address_or_contract = charter::schema::bytes_t{0x22},
                                          .enabled = true,
                                          .label = std::nullopt,
                                          .required_approvals = 2,
                                          .delay_ms = 10000}))
                  .code,
              0u);
    auto not_exec = finalize_single(
        engine, 17,
        make_tx(chain, 17, signer,
                charter::schema::apply_destination_update_t{
                    .workspace_id = ws,
                    .destination_id = dst,
                    .update_id = update2}));
    seen.insert(not_exec.code);
    EXPECT_EQ(not_exec.code, 39u);
  });

  run("20_28_29_30_34_35", [](auto& engine, auto& seen) {
    auto chain = chain_id_from_engine(engine);
    auto signer = make_named_signer(30);
    auto ws = make_hash(40);
    auto vault = make_hash(41);
    auto policy = make_hash(42);
    auto dst = make_hash(43);
    auto asset = make_hash(44);
    auto scope = charter::schema::policy_scope_t{
        charter::schema::vault_t{.workspace_id = ws, .vault_id = vault}};

    EXPECT_EQ(finalize_single(engine, 1,
                              make_tx(chain, 1, signer,
                                      charter::schema::create_workspace_t{
                                          .workspace_id = ws,
                                          .admin_set = {signer},
                                          .quorum_size = 1,
                                          .metadata_ref = std::nullopt}))
                  .code,
              0u);
    EXPECT_EQ(finalize_single(engine, 2,
                              make_tx(chain, 2, signer,
                                      charter::schema::create_vault_t{
                                          .workspace_id = ws,
                                          .vault_id = vault,
                                          .model = charter::schema::vault_model_t::segregated,
                                          .label = std::nullopt}))
                  .code,
              0u);
    EXPECT_EQ(finalize_single(engine, 3,
                              make_tx(chain, 3, signer,
                                      charter::schema::upsert_destination_t{
                                          .workspace_id = ws,
                                          .destination_id = dst,
                                          .type = charter::schema::destination_type_t::address,
                                          .chain_type = charter::schema::chain_type_t{
                                              charter::schema::chain_type::ethereum},
                                          .address_or_contract = charter::schema::bytes_t{0x01},
                                          .enabled = false,
                                          .label = std::nullopt}))
                  .code,
              0u);

    auto velocity_rule = charter::schema::velocity_limit_rule_t{};
    velocity_rule.operation = charter::schema::operation_type_t::transfer;
    velocity_rule.asset_id = asset;
    velocity_rule.window = charter::schema::velocity_window_t::daily;
    velocity_rule.maximum_amount = charter::schema::amount_t{5};
    auto sod_rule = charter::schema::approval_rule_t{
        .approver_role = charter::schema::role_id_t::approver,
        .threshold = 1,
        .require_distinct_from_initiator = true,
        .require_distinct_from_executor = false};
    auto claim_rule = make_transfer_rule(
        asset, 1, 0, std::nullopt, false,
        {charter::schema::claim_type_t{charter::schema::claim_type::kyb_verified}});
    claim_rule.approvals = {sod_rule};
    claim_rule.velocity_limits = {velocity_rule};
    claim_rule.destination_rules = {charter::schema::destination_rule_t{
        .require_whitelisted = true}};
    claim_rule.limits = {charter::schema::limit_rule_t{
        .asset_id = asset,
        .per_transaction_amount = charter::schema::amount_t{10}}};

    EXPECT_EQ(finalize_single(engine, 4,
                              make_tx(chain, 4, signer,
                                      charter::schema::create_policy_set_t{
                                          .policy_set_id = policy,
                                          .scope = scope,
                                          .policy_version = 1,
                                          .roles = {{charter::schema::role_id_t::approver, {signer}}},
                                          .rules = {claim_rule}}))
                  .code,
              0u);
    EXPECT_EQ(finalize_single(engine, 5,
                              make_tx(chain, 5, signer,
                                      charter::schema::activate_policy_set_t{
                                          .scope = scope,
                                          .policy_set_id = policy,
                                          .policy_set_version = 1}))
                  .code,
              0u);

    auto limit = finalize_single(
        engine, 6,
        make_tx(chain, 6, signer,
                charter::schema::propose_intent_t{
                    .workspace_id = ws,
                    .vault_id = vault,
                    .intent_id = make_hash(45),
                    .action = charter::schema::transfer_parameters_t{
                        .asset_id = asset,
                        .destination_id = dst,
                        .amount = 11},
                    .expires_at = std::nullopt}));
    seen.insert(limit.code);
    EXPECT_EQ(limit.code, 28u);

    auto whitelist = finalize_single(
        engine, 7,
        make_tx(chain, 7, signer,
                charter::schema::propose_intent_t{
                    .workspace_id = ws,
                    .vault_id = vault,
                    .intent_id = make_hash(46),
                    .action = charter::schema::transfer_parameters_t{
                        .asset_id = asset,
                        .destination_id = dst,
                        .amount = 5},
                    .expires_at = std::nullopt}));
    seen.insert(whitelist.code);
    EXPECT_EQ(whitelist.code, 29u);

    EXPECT_EQ(finalize_single(engine, 8,
                              make_tx(chain, 8, signer,
                                      charter::schema::upsert_destination_t{
                                          .workspace_id = ws,
                                          .destination_id = dst,
                                          .type = charter::schema::destination_type_t::address,
                                          .chain_type = charter::schema::chain_type_t{
                                              charter::schema::chain_type::ethereum},
                                          .address_or_contract = charter::schema::bytes_t{0x01},
                                          .enabled = true,
                                          .label = std::nullopt}))
                  .code,
              0u);

    auto velocity = finalize_single(
        engine, 9,
        make_tx(chain, 9, signer,
                charter::schema::propose_intent_t{
                    .workspace_id = ws,
                    .vault_id = vault,
                    .intent_id = make_hash(47),
                    .action = charter::schema::transfer_parameters_t{
                        .asset_id = asset,
                        .destination_id = dst,
                        .amount = 6},
                    .expires_at = std::nullopt}));
    seen.insert(velocity.code);
    EXPECT_EQ(velocity.code, 34u);

    EXPECT_EQ(finalize_single(engine, 10,
                              make_tx(chain, 10, signer,
                                      charter::schema::propose_intent_t{
                                          .workspace_id = ws,
                                          .vault_id = vault,
                                          .intent_id = make_hash(48),
                                          .action = charter::schema::transfer_parameters_t{
                                              .asset_id = asset,
                                              .destination_id = dst,
                                              .amount = 2},
                                          .expires_at = std::nullopt}))
                  .code,
              0u);

    auto sod = finalize_single(
        engine, 11,
        make_tx(chain, 11, signer,
                charter::schema::approve_intent_t{
                    .workspace_id = ws,
                    .vault_id = vault,
                    .intent_id = make_hash(48)}));
    seen.insert(sod.code);
    EXPECT_EQ(sod.code, 35u);

    EXPECT_EQ(finalize_single(engine, 12,
                              make_tx(chain, 12, signer,
                                      charter::schema::create_policy_set_t{
                                          .policy_set_id = make_hash(49),
                                          .scope = scope,
                                          .policy_version = 1,
                                          .roles = {{charter::schema::role_id_t::approver, {signer}}},
                                          .rules = {make_transfer_rule(asset, 1, 0, std::nullopt,
                                                                       false, {charter::schema::claim_type_t{
                                                                                    charter::schema::claim_type::kyb_verified}})}}))
                  .code,
              0u);
    EXPECT_EQ(finalize_single(engine, 13,
                              make_tx(chain, 13, signer,
                                      charter::schema::activate_policy_set_t{
                                          .scope = scope,
                                          .policy_set_id = make_hash(49),
                                          .policy_set_version = 1}))
                  .code,
              0u);
    EXPECT_EQ(finalize_single(engine, 14,
                              make_tx(chain, 14, signer,
                                      charter::schema::propose_intent_t{
                                          .workspace_id = ws,
                                          .vault_id = vault,
                                          .intent_id = make_hash(50),
                                          .action = charter::schema::transfer_parameters_t{
                                              .asset_id = asset,
                                              .destination_id = dst,
                                              .amount = 1},
                                          .expires_at = std::nullopt}))
                  .code,
              0u);
    EXPECT_EQ(finalize_single(engine, 15,
                              make_tx(chain, 15, signer,
                                      charter::schema::approve_intent_t{
                                          .workspace_id = ws,
                                          .vault_id = vault,
                                          .intent_id = make_hash(50)}))
                  .code,
              0u);
    auto claim = finalize_single(
        engine, 16,
        make_tx(chain, 16, signer,
                charter::schema::execute_intent_t{
                    .workspace_id = ws,
                    .vault_id = vault,
                    .intent_id = make_hash(50)}));
    seen.insert(claim.code);
    EXPECT_EQ(claim.code, 30u);
  });

  run("22_23_25_26", [](auto& engine, auto& seen) {
    auto chain = chain_id_from_engine(engine);
    auto signer = make_named_signer(40);
    auto ws = make_hash(60);
    auto vault = make_hash(61);
    auto policy = make_hash(62);
    auto dst = make_hash(63);
    auto asset = make_hash(64);
    auto scope = charter::schema::policy_scope_t{
        charter::schema::vault_t{.workspace_id = ws, .vault_id = vault}};
    EXPECT_EQ(finalize_single(engine, 1, make_tx(chain, 1, signer, charter::schema::create_workspace_t{
        .workspace_id = ws, .admin_set = {signer}, .quorum_size = 1, .metadata_ref = std::nullopt})).code, 0u);
    EXPECT_EQ(finalize_single(engine, 2, make_tx(chain, 2, signer, charter::schema::create_vault_t{
        .workspace_id = ws, .vault_id = vault, .model = charter::schema::vault_model_t::segregated, .label = std::nullopt})).code, 0u);
    EXPECT_EQ(finalize_single(engine, 3, make_tx(chain, 3, signer, charter::schema::upsert_destination_t{
        .workspace_id = ws, .destination_id = dst, .type = charter::schema::destination_type_t::address,
        .chain_type = charter::schema::chain_type_t{charter::schema::chain_type::ethereum},
        .address_or_contract = charter::schema::bytes_t{1}, .enabled = true, .label = std::nullopt})).code, 0u);
    EXPECT_EQ(finalize_single(engine, 4, make_tx(chain, 4, signer, charter::schema::create_policy_set_t{
        .policy_set_id = policy, .scope = scope, .policy_version = 1,
        .roles = {{charter::schema::role_id_t::approver, {signer}}},
        .rules = {make_transfer_rule(asset, 1, 0)}})).code, 0u);
    EXPECT_EQ(finalize_single(engine, 5, make_tx(chain, 5, signer, charter::schema::activate_policy_set_t{
        .scope = scope, .policy_set_id = policy, .policy_set_version = 1})).code, 0u);
    EXPECT_EQ(finalize_single(engine, 6, make_tx(chain, 6, signer, charter::schema::propose_intent_t{
        .workspace_id = ws, .vault_id = vault, .intent_id = make_hash(65),
        .action = charter::schema::transfer_parameters_t{.asset_id = asset, .destination_id = dst, .amount = 1},
        .expires_at = std::nullopt})).code, 0u);
    EXPECT_EQ(finalize_single(engine, 7, make_tx(chain, 7, signer, charter::schema::approve_intent_t{
        .workspace_id = ws, .vault_id = vault, .intent_id = make_hash(65)})).code, 0u);
    EXPECT_EQ(finalize_single(engine, 8, make_tx(chain, 8, signer, charter::schema::execute_intent_t{
        .workspace_id = ws, .vault_id = vault, .intent_id = make_hash(65)})).code, 0u);

    auto not_approvable = finalize_single(engine, 9, make_tx(chain, 9, signer, charter::schema::approve_intent_t{
        .workspace_id = ws, .vault_id = vault, .intent_id = make_hash(65)}));
    seen.insert(not_approvable.code);
    EXPECT_EQ(not_approvable.code, 22u);

    EXPECT_EQ(finalize_single(engine, 10, make_tx(chain, 10, signer, charter::schema::propose_intent_t{
        .workspace_id = ws, .vault_id = vault, .intent_id = make_hash(66),
        .action = charter::schema::transfer_parameters_t{.asset_id = asset, .destination_id = dst, .amount = 1},
        .expires_at = uint64_t{1000}})).code, 0u);
    auto expired_approve = finalize_single(engine, 12, make_tx(chain, 11, signer, charter::schema::approve_intent_t{
        .workspace_id = ws, .vault_id = vault, .intent_id = make_hash(66)}));
    seen.insert(expired_approve.code);
    EXPECT_EQ(expired_approve.code, 23u);

    auto not_exec = finalize_single(engine, 13, make_tx(chain, 12, signer, charter::schema::execute_intent_t{
        .workspace_id = ws, .vault_id = vault, .intent_id = make_hash(66)}));
    seen.insert(not_exec.code);
    EXPECT_EQ(not_exec.code, 23u);

    auto cancel_executed = finalize_single(engine, 14, make_tx(chain, 13, signer, charter::schema::cancel_intent_t{
        .workspace_id = ws, .vault_id = vault, .intent_id = make_hash(65)}));
    seen.insert(cancel_executed.code);
    EXPECT_EQ(cancel_executed.code, 25u);
  });

  run("20_corrupt", [](auto& engine, auto& seen) {
    auto encoder = encoder_t{};
    auto chain = chain_id_from_engine(engine);
    auto signer = make_named_signer(50);
    auto ws = make_hash(70);
    auto vault = make_hash(71);
    auto scope = charter::schema::policy_scope_t{
        charter::schema::vault_t{.workspace_id = ws, .vault_id = vault}};
    auto bad_policy_id = make_hash(72);
    auto workspace_key = prefixed_key("SYS|STATE|WORKSPACE|",
                                      charter::schema::bytes_t{std::begin(ws), std::end(ws)});
    auto vault_key = prefixed_key("SYS|STATE|VAULT|", encoder.encode(std::tuple{ws, vault}));
    auto active_key = prefixed_key("SYS|STATE|ACTIVE_POLICY|", encoder.encode(scope));
    auto rows = std::vector<charter::storage::key_value_entry_t>{
        {workspace_key, encoder.encode(charter::schema::workspace_state_t{
                            .workspace_id = ws, .admin_set = {signer}, .quorum_size = 1,
                            .metadata_ref = std::nullopt})},
        {vault_key, encoder.encode(charter::schema::vault_state_t{
                       .workspace_id = ws, .vault_id = vault,
                       .model = charter::schema::vault_model_t::segregated,
                       .label = std::nullopt})},
        {active_key, encoder.encode(charter::schema::active_policy_pointer_t{
                        .policy_set_id = bad_policy_id, .policy_set_version = 1})}};
    auto backup = make_state_backup(chain, rows);
    auto error = std::string{};
    ASSERT_TRUE(engine.import_backup(charter::schema::bytes_view_t{backup.data(), backup.size()},
                                     error))
        << error;
    auto tx = make_tx(chain, 1, signer, charter::schema::propose_intent_t{
        .workspace_id = ws,
        .vault_id = vault,
        .intent_id = make_hash(73),
        .action = charter::schema::transfer_parameters_t{
            .asset_id = make_hash(74), .destination_id = make_hash(75), .amount = 1},
        .expires_at = std::nullopt});
    auto result = finalize_single(engine, 1, tx);
    seen.insert(result.code);
    EXPECT_EQ(result.code, 20u);
  });

  run("26", [](auto& engine, auto& seen) {
    auto chain = chain_id_from_engine(engine);
    auto signer = make_named_signer(52);
    auto ws = make_hash(171);
    auto vault = make_hash(172);
    auto policy = make_hash(173);
    auto dst = make_hash(174);
    auto asset = make_hash(175);
    auto intent = make_hash(176);
    auto scope = charter::schema::policy_scope_t{
        charter::schema::vault_t{.workspace_id = ws, .vault_id = vault}};

    EXPECT_EQ(finalize_single(engine, 1, make_tx(chain, 1, signer, charter::schema::create_workspace_t{
        .workspace_id = ws, .admin_set = {signer}, .quorum_size = 1, .metadata_ref = std::nullopt})).code, 0u);
    EXPECT_EQ(finalize_single(engine, 2, make_tx(chain, 2, signer, charter::schema::create_vault_t{
        .workspace_id = ws, .vault_id = vault, .model = charter::schema::vault_model_t::segregated, .label = std::nullopt})).code, 0u);
    EXPECT_EQ(finalize_single(engine, 3, make_tx(chain, 3, signer, charter::schema::upsert_destination_t{
        .workspace_id = ws, .destination_id = dst, .type = charter::schema::destination_type_t::address,
        .chain_type = charter::schema::chain_type_t{charter::schema::chain_type::ethereum},
        .address_or_contract = charter::schema::bytes_t{0xAB}, .enabled = true, .label = std::nullopt})).code, 0u);
    EXPECT_EQ(finalize_single(engine, 4, make_tx(chain, 4, signer, charter::schema::create_policy_set_t{
        .policy_set_id = policy, .scope = scope, .policy_version = 1,
        .roles = {{charter::schema::role_id_t::approver, {signer}}},
        .rules = {make_transfer_rule(asset, 1, 10000)}})).code, 0u);
    EXPECT_EQ(finalize_single(engine, 5, make_tx(chain, 5, signer, charter::schema::activate_policy_set_t{
        .scope = scope, .policy_set_id = policy, .policy_set_version = 1})).code, 0u);
    EXPECT_EQ(finalize_single(engine, 6, make_tx(chain, 6, signer, charter::schema::propose_intent_t{
        .workspace_id = ws, .vault_id = vault, .intent_id = intent,
        .action = charter::schema::transfer_parameters_t{.asset_id = asset, .destination_id = dst, .amount = 1},
        .expires_at = std::nullopt})).code, 0u);
    EXPECT_EQ(finalize_single(engine, 7, make_tx(chain, 7, signer, charter::schema::approve_intent_t{
        .workspace_id = ws, .vault_id = vault, .intent_id = intent})).code, 0u);

    auto not_executable = finalize_single(engine, 8, make_tx(chain, 8, signer, charter::schema::execute_intent_t{
        .workspace_id = ws, .vault_id = vault, .intent_id = intent}));
    seen.insert(not_executable.code);
    EXPECT_EQ(not_executable.code, 26u);
  });

  run("31_32", [](auto& engine, auto& seen) {
    auto encoder = encoder_t{};
    auto chain = chain_id_from_engine(engine);
    auto signer = make_named_signer(60);

    auto quarantine_key =
        prefixed_key("SYS|STATE|SIGNER_QUARANTINE|", encoder.encode(signer));
    auto quarantine_value = encoder.encode(charter::schema::signer_quarantine_state_t{
        .signer = signer, .quarantined = true, .until = std::nullopt, .reason = std::nullopt});
    auto backup_quarantine =
        make_state_backup(chain, std::vector<charter::storage::key_value_entry_t>{
                                     {quarantine_key, quarantine_value}});
    auto error = std::string{};
    ASSERT_TRUE(engine.import_backup(
        charter::schema::bytes_view_t{backup_quarantine.data(), backup_quarantine.size()},
        error));
    auto tx31 = make_tx(chain, 1, signer, charter::schema::create_workspace_t{
        .workspace_id = make_hash(80), .admin_set = {signer}, .quorum_size = 1,
        .metadata_ref = std::nullopt});
    auto raw31 = encode_tx(tx31);
    auto check31 =
        engine.check_tx(charter::schema::bytes_view_t{raw31.data(), raw31.size()});
    seen.insert(check31.code);
    EXPECT_EQ(check31.code, 31u);

    auto degraded_key = prefixed_key(
        "SYS|STATE|DEGRADED_MODE|", charter::schema::make_bytes(std::string_view{"CURRENT"}));
    auto degraded_value = encoder.encode(charter::schema::degraded_mode_state_t{
        .mode = charter::schema::degraded_mode_t::read_only,
        .effective_at = std::nullopt,
        .reason = std::nullopt});
    auto backup_degraded =
        make_state_backup(chain, std::vector<charter::storage::key_value_entry_t>{
                                     {degraded_key, degraded_value}});
    ASSERT_TRUE(engine.import_backup(
        charter::schema::bytes_view_t{backup_degraded.data(), backup_degraded.size()},
        error));
    auto tx32 = make_tx(chain, 1, signer, charter::schema::create_workspace_t{
        .workspace_id = make_hash(81), .admin_set = {signer}, .quorum_size = 1,
        .metadata_ref = std::nullopt});
    auto raw32 = encode_tx(tx32);
    auto check32 =
        engine.check_tx(charter::schema::bytes_view_t{raw32.data(), raw32.size()});
    seen.insert(check32.code);
    EXPECT_EQ(check32.code, 32u);

  });

  run("33_denied", [](auto& engine, auto& seen) {
    auto chain = chain_id_from_engine(engine);
    auto admin = make_named_signer(70);
    auto other = make_named_signer(71);
    auto ws = make_hash(90);
    EXPECT_EQ(finalize_single(engine, 1, make_tx(chain, 1, admin, charter::schema::create_workspace_t{
        .workspace_id = ws, .admin_set = {admin}, .quorum_size = 1, .metadata_ref = std::nullopt})).code, 0u);
    auto denied = finalize_single(engine, 2, make_tx(chain, 1, other, charter::schema::create_vault_t{
        .workspace_id = ws, .vault_id = make_hash(91),
        .model = charter::schema::vault_model_t::segregated, .label = std::nullopt}));
    seen.insert(denied.code);
    EXPECT_EQ(denied.code, 33u);
  });

  auto expected = std::set<uint32_t>{
      1, 2, 3, 4, 5, 6, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
      21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
      37, 38, 39};
  EXPECT_EQ(observed, expected);
}

TEST(engine_integration, security_event_type_coverage) {
  auto db = make_db_path("charter_engine_events_coverage");
  {
    auto engine = charter::execution::engine{1, db, false};
    engine.set_signature_verifier([](const charter::schema::bytes_view_t &,
                                     const charter::schema::signer_id_t &,
                                     const charter::schema::signature_t &) {
      return true;
    });
    auto chain = chain_id_from_engine(engine);
    auto signer = make_named_signer(80);
    auto ws = make_hash(100);
    auto scope = charter::schema::policy_scope_t{
        charter::schema::workspace_scope_t{.workspace_id = ws}};

    auto malformed = charter::schema::bytes_t{0xFF, 0xEE, 0xDD};
    auto malformed_block = engine.finalize_block(1, {malformed});
    ASSERT_EQ(malformed_block.tx_results.size(), 1u);
    EXPECT_EQ(malformed_block.tx_results[0].code, 1u);
    (void)engine.commit();

    EXPECT_EQ(finalize_single(engine, 2, make_tx(chain, 1, signer, charter::schema::create_workspace_t{
        .workspace_id = ws, .admin_set = {signer}, .quorum_size = 1, .metadata_ref = std::nullopt})).code, 0u);
    auto denied = finalize_single(engine, 3, make_tx(chain, 2, signer, charter::schema::create_workspace_t{
        .workspace_id = ws, .admin_set = {signer}, .quorum_size = 1, .metadata_ref = std::nullopt}));
    EXPECT_EQ(denied.code, 10u);

    EXPECT_EQ(finalize_single(engine, 4, make_tx(chain, 3, signer, charter::schema::upsert_role_assignment_t{
        .scope = scope,
        .subject = signer,
        .role = charter::schema::role_id_t::admin,
        .enabled = true,
        .not_before = std::nullopt,
        .expires_at = std::nullopt,
        .note = std::nullopt})).code, 0u);

    auto bad_backup = charter::schema::bytes_t{1, 2, 3};
    auto import_error = std::string{};
    EXPECT_FALSE(engine.import_backup(
        charter::schema::bytes_view_t{bad_backup.data(), bad_backup.size()},
        import_error));

    auto backup = engine.export_backup();
    auto encoder = encoder_t{};
    auto decoded = encoder.decode<std::tuple<uint16_t,
                                             std::optional<charter::storage::committed_state>,
                                             std::vector<charter::storage::key_value_entry_t>,
                                             std::vector<charter::storage::key_value_entry_t>,
                                             std::vector<charter::storage::key_value_entry_t>,
                                             charter::schema::hash32_t>>(
        charter::schema::bytes_view_t{backup.data(), backup.size()});
    auto committed = std::get<1>(decoded);
    ASSERT_TRUE(committed.has_value());
    committed->app_hash[0] ^= 0x55;
    auto tampered = encoder.encode(std::tuple{std::get<0>(decoded), committed,
                                              std::get<2>(decoded), std::get<3>(decoded),
                                              std::get<4>(decoded), std::get<5>(decoded)});
    EXPECT_TRUE(engine.import_backup(
        charter::schema::bytes_view_t{tampered.data(), tampered.size()},
        import_error));
    auto replay = engine.replay_history();
    EXPECT_FALSE(replay.ok);
    EXPECT_FALSE(replay.error.empty());

    auto rejected = charter::execution::snapshot_descriptor{};
    rejected.height = 10;
    rejected.format = 2;
    rejected.chunks = 1;
    rejected.hash = make_hash(111);
    rejected.metadata = charter::schema::bytes_t{0x01};
    EXPECT_EQ(engine.offer_snapshot(rejected, rejected.hash),
              charter::execution::offer_snapshot_result::reject_format);

    auto snapshots = engine.list_snapshots();
    ASSERT_FALSE(snapshots.empty());
    auto offered = snapshots.front();
    EXPECT_EQ(engine.offer_snapshot(offered, offered.hash),
              charter::execution::offer_snapshot_result::accept);
    auto chunk =
        engine.load_snapshot_chunk(offered.height, offered.format, 0);
    ASSERT_TRUE(chunk.has_value());
    EXPECT_EQ(engine.apply_snapshot_chunk(
                  0, charter::schema::bytes_view_t{chunk->data(), chunk->size()},
                  "peer-1"),
              charter::execution::apply_snapshot_chunk_result::accept);

    auto events = query_events(engine, 1, 1000);
    auto types = std::set<charter::schema::security_event_type_t>{};
    for (const auto& event : events) {
      types.insert(event.type);
    }
    auto numeric_types = std::set<uint16_t>{};
    for (const auto type : types) {
      numeric_types.insert(static_cast<uint16_t>(type));
    }
    EXPECT_EQ(numeric_types, (std::set<uint16_t>{6u, 7u, 8u, 9u}));
  }
  std::error_code ec;
  std::filesystem::remove_all(db, ec);
}

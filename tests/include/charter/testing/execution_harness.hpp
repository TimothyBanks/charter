#pragma once

#include <gtest/gtest.h>

#include <charter/execution/engine.hpp>
#include <charter/schema/active_policy_pointer.hpp>
#include <charter/schema/encoding/scale/encoder.hpp>
#include <charter/schema/intent_state.hpp>
#include <charter/storage/storage.hpp>
#include <charter/testing/common.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace charter::testing {

using scale_encoder_t = charter::schema::encoding::encoder<
    charter::schema::encoding::scale_encoder_tag>;

inline charter::schema::transaction_t make_transaction(
    const charter::schema::hash32_t& chain_id,
    const uint64_t nonce,
    const charter::schema::signer_id_t& signer,
    const charter::schema::transaction_payload_t& payload) {
  return charter::schema::transaction_t{
      .version = 1,
      .chain_id = chain_id,
      .nonce = nonce,
      .signer = signer,
      .payload = payload,
      .signature = charter::schema::ed25519_signature_t{}};
}

inline charter::schema::bytes_t encode_transaction(
    const charter::schema::transaction_t& tx) {
  auto encoder = scale_encoder_t{};
  return encoder.encode(tx);
}

inline charter::schema::hash32_t chain_id_from_engine(
    charter::execution::engine& engine) {
  const auto query = engine.query("/engine/info", {});
  EXPECT_EQ(query.code, 0u);
  auto encoder = scale_encoder_t{};
  const auto decoded = encoder.decode<std::tuple<
      int64_t, charter::schema::hash32_t, charter::schema::hash32_t>>(
      charter::schema::bytes_view_t{query.value.data(), query.value.size()});
  return std::get<2>(decoded);
}

inline charter::schema::transaction_result_t finalize_single(
    charter::execution::engine& engine,
    const uint64_t height,
    const charter::schema::transaction_t& tx) {
  const auto signer_nonce_key = [](const charter::schema::signer_id_t& signer) {
    auto key = std::string{};
    std::visit(
        ::overloaded{
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
              key.append(reinterpret_cast<const char*>(value.data()),
                         value.size());
            }},
        signer);
    return key;
  };

  static auto nonce_state =
      std::map<std::uintptr_t, std::map<std::string, uint64_t>>{};
  const auto engine_key = reinterpret_cast<std::uintptr_t>(&engine);
  const auto signer_key = signer_nonce_key(tx.signer);
  auto& signer_nonces = nonce_state[engine_key];
  auto& expected = signer_nonces[signer_key];
  if (expected == 0) {
    expected = tx.nonce;
  }

  auto normalized = tx;
  normalized.nonce = expected;
  auto block = engine.finalize_block(height, {encode_transaction(normalized)});
  EXPECT_EQ(block.tx_results.size(), 1u);
  auto result = block.tx_results.front();
  if (result.code == 0) {
    ++expected;
  }
  (void)engine.commit();
  return result;
}

inline std::vector<charter::schema::security_event_record_t> query_events(
    charter::execution::engine& engine,
    const uint64_t from_id,
    const uint64_t to_id) {
  auto encoder = scale_encoder_t{};
  const auto query_key = encoder.encode(std::tuple{from_id, to_id});
  const auto result = engine.query(
      "/events/range",
      charter::schema::bytes_view_t{query_key.data(), query_key.size()});
  EXPECT_EQ(result.code, 0u);
  return encoder.decode<std::vector<charter::schema::security_event_record_t>>(
      charter::schema::bytes_view_t{result.value.data(), result.value.size()});
}

inline charter::schema::bytes_t make_state_backup(
    const charter::schema::hash32_t& chain_id,
    const std::vector<charter::storage::key_value_entry_t>& state_rows) {
  auto encoder = scale_encoder_t{};
  auto history_rows = std::vector<charter::storage::key_value_entry_t>{};
  auto snapshots = std::vector<charter::storage::key_value_entry_t>{};
  return encoder.encode(std::tuple{
      uint16_t{1}, std::optional<charter::storage::committed_state>{},
      state_rows, history_rows, snapshots, chain_id});
}

inline charter::schema::bytes_t prefixed_key(
    const std::string_view prefix,
    const charter::schema::bytes_t& suffix) {
  auto codec = scale_encoder_t{};
  auto out = codec.encode(prefix);
  out.insert(std::end(out), std::begin(suffix), std::end(suffix));
  return out;
}

inline charter::schema::policy_rule_t make_transfer_rule(
    const charter::schema::hash32_t& asset_id,
    const uint32_t threshold,
    const uint64_t timelock_ms,
    std::optional<uint64_t> limit_amount = std::nullopt,
    const bool require_whitelist = false,
    std::vector<charter::schema::claim_type_t> required_claims = {}) {
  const auto approval = charter::schema::approval_rule_t{
      .approver_role = charter::schema::role_id_t::approver,
      .threshold = threshold,
      .require_distinct_from_initiator = false,
      .require_distinct_from_executor = false};
  const auto time_lock = charter::schema::time_lock_rule_t{
      .operation = charter::schema::operation_type_t::transfer,
      .delay = timelock_ms};
  return charter::schema::policy_rule_t{
      .operation = charter::schema::operation_type_t::transfer,
      .approvals = {approval},
      .limits =
          limit_amount.has_value()
              ? std::vector<charter::schema::
                                limit_rule_t>{charter::schema::limit_rule_t{
                    .asset_id = asset_id,
                    .per_transaction_amount =
                        charter::schema::amount_t{limit_amount.value()}}}
              : std::vector<charter::schema::limit_rule_t>{},
      .time_locks = std::vector{time_lock},
      .destination_rules =
          require_whitelist
              ? std::vector<
                    charter::schema::
                        destination_rule_t>{charter::schema::destination_rule_t{
                    .require_whitelisted = true}}
              : std::vector<charter::schema::destination_rule_t>{},
      .required_claims = std::move(required_claims),
      .velocity_limits = {}};
}

inline charter::schema::upsert_asset_t make_upsert_asset(
    const charter::schema::hash32_t& asset_id,
    const bool enabled = true) {
  return charter::schema::upsert_asset_t{
      .asset_id = asset_id,
      .chain =
          charter::schema::chain_type_t{charter::schema::chain_type::ethereum},
      .kind = charter::schema::asset_kind_t::erc20,
      .reference =
          charter::schema::asset_ref_contract_address_t{
              .address = charter::schema::bytes_t{0xAA, 0xBB}},
      .symbol = charter::schema::make_bytes(std::string_view{"TOK"}),
      .name = charter::schema::make_bytes(std::string_view{"Token"}),
      .decimals = 18,
      .enabled = enabled};
}

}  // namespace charter::testing

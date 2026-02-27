#include <charter/schema/encoding/scale/encoder.hpp>
#include <charter/schema/create_workspace.hpp>
#include <charter/schema/policy_rule.hpp>
#include <charter/schema/security_event_record.hpp>
#include <charter/schema/transaction.hpp>
#include <gtest/gtest.h>
#include <string>
#include <string_view>

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

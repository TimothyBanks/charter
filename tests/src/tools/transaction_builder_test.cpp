#include <gtest/gtest.h>
#include <charter/schema/encoding/scale/encoder.hpp>
#include <charter/schema/intent_state.hpp>
#include <charter/schema/primitives.hpp>
#include <charter/schema/role_id.hpp>
#include <charter/schema/transaction.hpp>

#include <array>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include <sys/wait.h>

#ifndef CHARTER_TRANSACTION_BUILDER_PATH
#define CHARTER_TRANSACTION_BUILDER_PATH ""
#endif

namespace {

using encoder_t = charter::schema::encoding::encoder<
    charter::schema::encoding::scale_encoder_tag>;

std::string shell_quote(const std::string_view value) {
  auto out = std::string{"'"};
  for (const auto ch : value) {
    if (ch == '\'') {
      out += "'\\''";
    } else {
      out.push_back(ch);
    }
  }
  out.push_back('\'');
  return out;
}

std::string trim_ascii_whitespace(const std::string& input) {
  auto first = size_t{0};
  while (first < input.size() &&
         std::isspace(static_cast<unsigned char>(input[first])) != 0) {
    ++first;
  }
  auto last = input.size();
  while (last > first &&
         std::isspace(static_cast<unsigned char>(input[last - 1])) != 0) {
    --last;
  }
  return input.substr(first, last - first);
}

std::pair<int, std::string> run_capture(const std::string& command) {
  auto buffer = std::array<char, 256>{};
  auto output = std::string{};
  auto* pipe = popen(command.c_str(), "r");
  if (pipe == nullptr) {
    return {-1, {}};
  }
  while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) !=
         nullptr) {
    output += buffer.data();
  }
  auto status = pclose(pipe);
  if (status == -1) {
    return {-1, output};
  }
  if (WIFEXITED(status) == 0) {
    return {-1, output};
  }
  return {WEXITSTATUS(status), output};
}

std::string run_query_key_command(const std::string& builder,
                                  const std::string_view args) {
  auto command = shell_quote(builder) + " query-key " + std::string{args};
  auto [exit_code, output] = run_capture(command);
  EXPECT_EQ(exit_code, 0) << "command failed: " << command << '\n' << output;
  return trim_ascii_whitespace(output);
}

std::string run_transaction_command(const std::string& builder,
                                    const std::string_view args) {
  auto command = shell_quote(builder) + " transaction " + std::string{args};
  auto [exit_code, output] = run_capture(command);
  EXPECT_EQ(exit_code, 0) << "command failed: " << command << '\n' << output;
  return trim_ascii_whitespace(output);
}

std::string run_decode_intent_state_command(const std::string& builder,
                                            const std::string_view args) {
  auto command =
      shell_quote(builder) + " decode-intent-state " + std::string{args};
  auto [exit_code, output] = run_capture(command);
  EXPECT_EQ(exit_code, 0) << "command failed: " << command << '\n' << output;
  return trim_ascii_whitespace(output);
}

}  // namespace

TEST(transaction_builder,
     query_key_matches_route_contract_for_proof_script_paths) {
  auto builder = std::string{CHARTER_TRANSACTION_BUILDER_PATH};
  if (builder.empty() || !std::filesystem::exists(builder)) {
    GTEST_SKIP() << "transaction_builder binary not available: " << builder;
  }

  constexpr auto kWorkspaceId =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  constexpr auto kVaultId =
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  constexpr auto kIntentId =
      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
  constexpr auto kAssetId =
      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
  constexpr auto kDestinationId =
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  constexpr auto kUpdateId =
      "abababababababababababababababababababababababababababababababab";
  constexpr auto kSubjectSigner =
      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

  auto encoder = encoder_t{};

  auto expected_intent_key = encoder.encode(
      std::tuple{charter::schema::make_hash32(std::string{kWorkspaceId}),
                 charter::schema::make_hash32(std::string{kVaultId}),
                 charter::schema::make_hash32(std::string{kIntentId})});
  auto intent_actual = run_query_key_command(
      builder, "--path /state/intent --workspace-id " +
                   std::string{kWorkspaceId} + " --vault-id " +
                   std::string{kVaultId} + " --intent-id " +
                   std::string{kIntentId});
  EXPECT_EQ(intent_actual, charter::schema::to_base64(expected_intent_key));

  auto expected_history_key =
      encoder.encode(std::tuple{uint64_t{1}, uint64_t{100}});
  auto history_actual = run_query_key_command(
      builder, "--path /history/range --from-height 1 --to-height 100");
  EXPECT_EQ(history_actual, charter::schema::to_base64(expected_history_key));

  auto asset_hash = charter::schema::make_hash32(std::string{kAssetId});
  auto expected_asset_key =
      charter::schema::bytes_t{std::begin(asset_hash), std::end(asset_hash)};
  auto asset_actual = run_query_key_command(
      builder, "--path /state/asset --asset-id " + std::string{kAssetId});
  EXPECT_EQ(asset_actual, charter::schema::to_base64(expected_asset_key));

  auto expected_role_assignment_key = encoder.encode(std::tuple{
      charter::schema::policy_scope_t{charter::schema::workspace_scope_t{
          .workspace_id =
              charter::schema::make_hash32(std::string{kWorkspaceId})}},
      charter::schema::signer_id_t{
          charter::schema::make_hash32(std::string{kSubjectSigner})},
      charter::schema::role_id_t::admin});
  auto role_assignment_actual = run_query_key_command(
      builder,
      "--path /state/role_assignment --scope-type workspace "
      "--workspace-id " +
          std::string{kWorkspaceId} + " --subject-signer " +
          std::string{kSubjectSigner} + " --role admin");
  EXPECT_EQ(role_assignment_actual,
            charter::schema::to_base64(expected_role_assignment_key));

  auto expected_signer_quarantine_key =
      encoder.encode(charter::schema::signer_id_t{
          charter::schema::make_hash32(std::string{kSubjectSigner})});
  auto signer_quarantine_actual =
      run_query_key_command(builder,
                            "--path /state/signer_quarantine "
                            "--target-signer " +
                                std::string{kSubjectSigner});
  EXPECT_EQ(signer_quarantine_actual,
            charter::schema::to_base64(expected_signer_quarantine_key));

  auto expected_destination_update_key = encoder.encode(
      std::tuple{charter::schema::make_hash32(std::string{kWorkspaceId}),
                 charter::schema::make_hash32(std::string{kDestinationId}),
                 charter::schema::make_hash32(std::string{kUpdateId})});
  auto destination_update_actual = run_query_key_command(
      builder, "--path /state/destination_update --workspace-id " +
                   std::string{kWorkspaceId} + " --destination-id " +
                   std::string{kDestinationId} + " --update-id " +
                   std::string{kUpdateId});
  EXPECT_EQ(destination_update_actual,
            charter::schema::to_base64(expected_destination_update_key));

  auto degraded_mode_actual =
      run_query_key_command(builder, "--path /state/degraded_mode");
  EXPECT_TRUE(degraded_mode_actual.empty());
}

TEST(transaction_builder, supports_extended_payload_build_commands) {
  auto builder = std::string{CHARTER_TRANSACTION_BUILDER_PATH};
  if (builder.empty() || !std::filesystem::exists(builder)) {
    GTEST_SKIP() << "transaction_builder binary not available: " << builder;
  }

  constexpr auto kChainId =
      "1111111111111111111111111111111111111111111111111111111111111111";
  constexpr auto kSigner =
      "2222222222222222222222222222222222222222222222222222222222222222";
  constexpr auto kWorkspaceId =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  constexpr auto kVaultId =
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  constexpr auto kIntentId =
      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
  constexpr auto kDestinationId =
      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
  constexpr auto kUpdateId =
      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
  constexpr auto kTargetSigner =
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

  auto cancel_intent = run_transaction_command(
      builder, "--payload cancel_intent --chain-id " + std::string{kChainId} +
                   " --nonce 1 --signer " + std::string{kSigner} +
                   " --workspace-id " + std::string{kWorkspaceId} +
                   " --vault-id " + std::string{kVaultId} + " --intent-id " +
                   std::string{kIntentId});
  EXPECT_FALSE(cancel_intent.empty());

  auto propose_destination_update = run_transaction_command(
      builder, "--payload propose_destination_update --chain-id " +
                   std::string{kChainId} + " --nonce 2 --signer " +
                   std::string{kSigner} + " --workspace-id " +
                   std::string{kWorkspaceId} + " --destination-id " +
                   std::string{kDestinationId} + " --update-id " +
                   std::string{kUpdateId} +
                   " --destination-type address --chain ethereum "
                   "--address-or-contract-hex aabb --destination-enabled true "
                   "--required-approvals 2 --delay-ms 1000");
  EXPECT_FALSE(propose_destination_update.empty());

  auto approve_destination_update = run_transaction_command(
      builder, "--payload approve_destination_update --chain-id " +
                   std::string{kChainId} + " --nonce 3 --signer " +
                   std::string{kSigner} + " --workspace-id " +
                   std::string{kWorkspaceId} + " --destination-id " +
                   std::string{kDestinationId} + " --update-id " +
                   std::string{kUpdateId});
  EXPECT_FALSE(approve_destination_update.empty());

  auto apply_destination_update = run_transaction_command(
      builder, "--payload apply_destination_update --chain-id " +
                   std::string{kChainId} + " --nonce 4 --signer " +
                   std::string{kSigner} + " --workspace-id " +
                   std::string{kWorkspaceId} + " --destination-id " +
                   std::string{kDestinationId} + " --update-id " +
                   std::string{kUpdateId});
  EXPECT_FALSE(apply_destination_update.empty());

  auto upsert_role_assignment = run_transaction_command(
      builder,
      "--payload upsert_role_assignment --chain-id " + std::string{kChainId} +
          " --nonce 5 --signer " + std::string{kSigner} +
          " --scope-type vault "
          "--workspace-id " +
          std::string{kWorkspaceId} + " --vault-id " + std::string{kVaultId} +
          " --subject-signer " + std::string{kTargetSigner} +
          " --role approver --role-enabled true --role-not-before 10 "
          "--role-expires-at 20 --role-note-hex 616263");
  EXPECT_FALSE(upsert_role_assignment.empty());

  auto upsert_signer_quarantine = run_transaction_command(
      builder, "--payload upsert_signer_quarantine --chain-id " +
                   std::string{kChainId} + " --nonce 6 --signer " +
                   std::string{kSigner} + " --target-signer " +
                   std::string{kTargetSigner} +
                   " --quarantined true --quarantine-until 30 "
                   "--quarantine-reason-hex 7269736b");
  EXPECT_FALSE(upsert_signer_quarantine.empty());

  auto set_degraded_mode = run_transaction_command(
      builder, "--payload set_degraded_mode --chain-id " +
                   std::string{kChainId} + " --nonce 7 --signer " +
                   std::string{kSigner} +
                   " --degraded-mode read_only --effective-at 40 "
                   "--degraded-reason-hex 6d61696e74656e616e6365");
  EXPECT_FALSE(set_degraded_mode.empty());
}

TEST(transaction_builder,
     create_workspace_defaults_admin_set_to_signer_when_admin_omitted) {
  auto builder = std::string{CHARTER_TRANSACTION_BUILDER_PATH};
  if (builder.empty() || !std::filesystem::exists(builder)) {
    GTEST_SKIP() << "transaction_builder binary not available: " << builder;
  }

  constexpr auto kChainId =
      "1111111111111111111111111111111111111111111111111111111111111111";
  constexpr auto kSigner =
      "2222222222222222222222222222222222222222222222222222222222222222";
  constexpr auto kWorkspaceId =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

  auto tx_b64 = run_transaction_command(
      builder, "--payload create_workspace --chain-id " +
                   std::string{kChainId} + " --nonce 1 --signer " +
                   std::string{kSigner} + " --workspace-id " +
                   std::string{kWorkspaceId});
  auto tx_bytes = charter::schema::from_base64(tx_b64);
  auto encoder = encoder_t{};
  auto tx = encoder.decode<charter::schema::transaction_t>(
      charter::schema::bytes_view_t{tx_bytes.data(), tx_bytes.size()});

  ASSERT_TRUE(
      std::holds_alternative<charter::schema::create_workspace_t>(tx.payload));
  auto workspace = std::get<charter::schema::create_workspace_t>(tx.payload);
  ASSERT_EQ(workspace.admin_set.size(), 1u);
  EXPECT_EQ(encoder.encode(workspace.admin_set.front()), encoder.encode(tx.signer));
}

TEST(transaction_builder, decode_intent_state_reports_executed_status) {
  auto builder = std::string{CHARTER_TRANSACTION_BUILDER_PATH};
  if (builder.empty() || !std::filesystem::exists(builder)) {
    GTEST_SKIP() << "transaction_builder binary not available: " << builder;
  }

  constexpr auto kWorkspaceId =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  constexpr auto kVaultId =
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  constexpr auto kIntentId =
      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
  constexpr auto kSigner =
      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
  constexpr auto kAssetId =
      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
  constexpr auto kDestinationId =
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  constexpr auto kPolicySetId =
      "abababababababababababababababababababababababababababababababab";

  auto intent_state = charter::schema::intent_state_t{
      .workspace_id = charter::schema::make_hash32(std::string{kWorkspaceId}),
      .vault_id = charter::schema::make_hash32(std::string{kVaultId}),
      .intent_id = charter::schema::make_hash32(std::string{kIntentId}),
      .created_by = charter::schema::signer_id_t{charter::schema::make_hash32(
          std::string{kSigner})},
      .created_at = 1,
      .not_before = 1,
      .expires_at = std::nullopt,
      .action =
          charter::schema::transfer_parameters_t{
              .asset_id = charter::schema::make_hash32(std::string{kAssetId}),
              .destination_id =
                  charter::schema::make_hash32(std::string{kDestinationId}),
              .amount = 42},
      .status = charter::schema::intent_status_t::executed,
      .policy_set_id = charter::schema::make_hash32(std::string{kPolicySetId}),
      .policy_version = 1,
      .required_threshold = 1,
      .approvals_count = 1,
      .claim_requirements = {}};
  auto encoded = encoder_t{}.encode(intent_state);
  auto actual = run_decode_intent_state_command(
      builder, "--value-base64 " + charter::schema::to_base64(encoded));
  EXPECT_EQ(actual, "executed");
}

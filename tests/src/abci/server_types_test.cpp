#include <gtest/gtest.h>
#include <charter/abci/server.hpp>
#include <charter/schema/encoding/scale/encoder.hpp>
#include <charter/storage/rocksdb/storage.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <tuple>

namespace {

using encoder_t = charter::schema::encoding::encoder<
    charter::schema::encoding::scale_encoder_tag>;

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

charter::schema::transaction_t make_create_workspace_transaction(
    const charter::schema::hash32_t& chain_id,
    const uint64_t nonce,
    const charter::schema::signer_id_t& signer,
    const charter::schema::hash32_t& workspace_id) {
  return charter::schema::transaction_t{
      .version = 1,
      .chain_id = chain_id,
      .nonce = nonce,
      .signer = signer,
      .payload =
          charter::schema::create_workspace_t{.workspace_id = workspace_id,
                                              .admin_set = {signer},
                                              .quorum_size = 1,
                                              .metadata_ref = std::nullopt},
      .signature = charter::schema::ed25519_signature_t{}};
}

charter::schema::bytes_t encode_transaction(
    const charter::schema::transaction_t& transaction) {
  auto encoder = encoder_t{};
  return encoder.encode(transaction);
}

charter::schema::hash32_t chain_id_from_engine(
    charter::execution::engine& engine) {
  auto query = engine.query("/engine/info", {});
  EXPECT_EQ(query.code, 0u);
  auto encoder = encoder_t{};
  auto decoded = encoder.decode<std::tuple<int64_t, charter::schema::hash32_t,
                                           charter::schema::hash32_t>>(
      charter::schema::bytes_view_t{query.value.data(), query.value.size()});
  return std::get<2>(decoded);
}

std::string make_db_path(const std::string& prefix) {
  auto now =
      std::chrono::high_resolution_clock::now().time_since_epoch().count();
  auto path =
      std::filesystem::temp_directory_path() /
      (prefix + "_" + std::to_string(static_cast<unsigned long long>(now)));
  return path.string();
}

}  // namespace

TEST(abci_server, prepare_proposal_filters_invalid_and_respects_max_bytes) {
  auto db = make_db_path("charter_abci_prepare");
  {
    auto encoder = encoder_t{};
    auto storage =
        charter::storage::make_storage<charter::storage::rocksdb_storage_tag>(
            db);
    auto engine = charter::execution::engine{encoder, storage, 1, false};
    engine.set_signature_verifier(
        [](const charter::schema::bytes_view_t&,
           const charter::schema::signer_id_t&,
           const charter::schema::signature_t&) { return true; });

    auto chain_id = chain_id_from_engine(engine);
    auto signer_1 = make_named_signer(0x11);
    auto signer_2 = make_named_signer(0x22);
    auto tx_1 = encode_transaction(make_create_workspace_transaction(
        chain_id, 1, signer_1, make_hash(0x31)));
    auto tx_2 = encode_transaction(make_create_workspace_transaction(
        chain_id, 1, signer_2, make_hash(0x41)));

    auto invalid = charter::schema::bytes_t{0xFF, 0x00, 0x01};

    auto request = tendermint::abci::RequestPrepareProposal{};
    request.set_max_tx_bytes(static_cast<int64_t>(tx_1.size()));
    *request.add_txs() = charter::schema::make_string(invalid);
    *request.add_txs() = charter::schema::make_string(tx_1);
    *request.add_txs() = charter::schema::make_string(tx_2);

    auto response = tendermint::abci::ResponsePrepareProposal{};
    auto context = grpc::CallbackServerContext{};
    auto listener = charter::abci::listener{engine};
    auto* reactor = listener.PrepareProposal(&context, &request, &response);
    ASSERT_NE(reactor, nullptr);
    ASSERT_EQ(response.txs_size(), 1);
    EXPECT_EQ(response.txs(0), charter::schema::make_string(tx_1));
  }

  auto error = std::error_code{};
  std::filesystem::remove_all(db, error);
}

TEST(abci_server, process_proposal_rejects_invalid_and_accepts_valid) {
  auto db = make_db_path("charter_abci_process");
  {
    auto encoder = encoder_t{};
    auto storage =
        charter::storage::make_storage<charter::storage::rocksdb_storage_tag>(
            db);
    auto engine = charter::execution::engine{encoder, storage, 1, false};
    engine.set_signature_verifier(
        [](const charter::schema::bytes_view_t&,
           const charter::schema::signer_id_t&,
           const charter::schema::signature_t&) { return true; });
    auto listener = charter::abci::listener{engine};

    {
      auto request = tendermint::abci::RequestProcessProposal{};
      *request.add_txs() = std::string{"\xAA\xBB\xCC", 3};
      auto response = tendermint::abci::ResponseProcessProposal{};
      auto context = grpc::CallbackServerContext{};
      auto* reactor = listener.ProcessProposal(&context, &request, &response);
      ASSERT_NE(reactor, nullptr);
      EXPECT_EQ(
          response.status(),
          tendermint::abci::ResponseProcessProposal_ProposalStatus_REJECT);
    }

    {
      auto chain_id = chain_id_from_engine(engine);
      auto signer = make_named_signer(0x33);
      auto tx = encode_transaction(make_create_workspace_transaction(
          chain_id, 1, signer, make_hash(0x51)));

      auto request = tendermint::abci::RequestProcessProposal{};
      *request.add_txs() = charter::schema::make_string(tx);
      auto response = tendermint::abci::ResponseProcessProposal{};
      auto context = grpc::CallbackServerContext{};
      auto* reactor = listener.ProcessProposal(&context, &request, &response);
      ASSERT_NE(reactor, nullptr);
      EXPECT_EQ(
          response.status(),
          tendermint::abci::ResponseProcessProposal_ProposalStatus_ACCEPT);
    }
  }

  auto error = std::error_code{};
  std::filesystem::remove_all(db, error);
}

TEST(abci_server, finalize_block_maps_exec_results_and_state_root) {
  auto db = make_db_path("charter_abci_finalize");
  {
    auto encoder = encoder_t{};
    auto storage =
        charter::storage::make_storage<charter::storage::rocksdb_storage_tag>(
            db);
    auto engine = charter::execution::engine{encoder, storage, 1, false};
    engine.set_signature_verifier(
        [](const charter::schema::bytes_view_t&,
           const charter::schema::signer_id_t&,
           const charter::schema::signature_t&) { return true; });
    auto listener = charter::abci::listener{engine};

    auto chain_id = chain_id_from_engine(engine);
    auto signer = make_named_signer(0x44);
    auto transaction = encode_transaction(make_create_workspace_transaction(
        chain_id, 1, signer, make_hash(0x61)));

    auto request = tendermint::abci::RequestFinalizeBlock{};
    request.set_height(1);
    *request.add_txs() = charter::schema::make_string(transaction);

    auto response = tendermint::abci::ResponseFinalizeBlock{};
    auto context = grpc::CallbackServerContext{};
    auto* reactor = listener.FinalizeBlock(&context, &request, &response);
    ASSERT_NE(reactor, nullptr);
    ASSERT_EQ(response.tx_results_size(), 1);
    EXPECT_EQ(response.tx_results(0).code(), 0u);
    ASSERT_GT(response.tx_results(0).events_size(), 0);
    EXPECT_EQ(response.tx_results(0).events(0).type(), "charter.tx_result");
    ASSERT_EQ(response.app_hash().size(), 32);

    auto commit = engine.commit();
    auto committed = charter::schema::bytes_t{std::begin(commit.state_root),
                                              std::end(commit.state_root)};
    EXPECT_EQ(committed, charter::schema::make_bytes(response.app_hash()));
  }

  auto error = std::error_code{};
  std::filesystem::remove_all(db, error);
}

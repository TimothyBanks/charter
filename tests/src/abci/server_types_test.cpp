#include <gtest/gtest.h>
#include <charter/abci/server.hpp>
#include <charter/storage/rocksdb/storage.hpp>
#include <charter/testing/abci_harness.hpp>

#include <string>

namespace {

using encoder_t = charter::testing::scale_encoder_t;
using charter::testing::chain_id_from_engine;
using charter::testing::encode_transaction;
using charter::testing::make_create_workspace_transaction;
using charter::testing::make_db_path;
using charter::testing::make_hash;
using charter::testing::make_named_signer;
using charter::testing::remove_path;

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

  remove_path(db);
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

  remove_path(db);
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

  remove_path(db);
}

#include <spdlog/spdlog.h>
#include <charter/abci/server.hpp>
#include <iterator>
#include <string>
#include <vector>

using namespace charter::abci;
using namespace charter::schema;

namespace {

grpc::ServerUnaryReactor* finish_ok(grpc::CallbackServerContext* context) {
  auto* reactor = context->DefaultReactor();
  reactor->Finish(grpc::Status::OK);
  return reactor;
}

tendermint::abci::ResponseOfferSnapshot_Result map_offer_result(
    charter::execution::offer_snapshot_result result) {
  switch (result) {
    case charter::execution::offer_snapshot_result::accept:
      return tendermint::abci::ResponseOfferSnapshot_Result_ACCEPT;
    case charter::execution::offer_snapshot_result::abort:
      return tendermint::abci::ResponseOfferSnapshot_Result_ABORT;
    case charter::execution::offer_snapshot_result::reject:
      return tendermint::abci::ResponseOfferSnapshot_Result_REJECT;
    case charter::execution::offer_snapshot_result::reject_format:
      return tendermint::abci::ResponseOfferSnapshot_Result_REJECT_FORMAT;
    case charter::execution::offer_snapshot_result::reject_sender:
      return tendermint::abci::ResponseOfferSnapshot_Result_REJECT_SENDER;
    case charter::execution::offer_snapshot_result::unknown:
    default:
      return tendermint::abci::ResponseOfferSnapshot_Result_UNKNOWN;
  }
}

tendermint::abci::ResponseApplySnapshotChunk_Result map_apply_result(
    charter::execution::apply_snapshot_chunk_result result) {
  switch (result) {
    case charter::execution::apply_snapshot_chunk_result::accept:
      return tendermint::abci::ResponseApplySnapshotChunk_Result_ACCEPT;
    case charter::execution::apply_snapshot_chunk_result::abort:
      return tendermint::abci::ResponseApplySnapshotChunk_Result_ABORT;
    case charter::execution::apply_snapshot_chunk_result::retry:
      return tendermint::abci::ResponseApplySnapshotChunk_Result_RETRY;
    case charter::execution::apply_snapshot_chunk_result::retry_snapshot:
      return tendermint::abci::ResponseApplySnapshotChunk_Result_RETRY_SNAPSHOT;
    case charter::execution::apply_snapshot_chunk_result::reject_snapshot:
      return tendermint::abci::
          ResponseApplySnapshotChunk_Result_REJECT_SNAPSHOT;
    case charter::execution::apply_snapshot_chunk_result::unknown:
    default:
      return tendermint::abci::ResponseApplySnapshotChunk_Result_UNKNOWN;
  }
}

void populate_exec_tx_result(const charter::execution::tx_result& source,
                             tendermint::abci::ExecTxResult* destination) {
  destination->set_code(source.code);
  destination->set_data(make_string(source.data));
  destination->set_log(source.log);
  destination->set_info(source.info);
  destination->set_gas_wanted(source.gas_wanted);
  destination->set_gas_used(source.gas_used);
  destination->set_codespace(source.codespace);
}

}  // namespace

void reactor::OnDone() {}

grpc::ServerUnaryReactor* listener::Echo(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestEcho* request,
    tendermint::abci::ResponseEcho* response) {
  response->set_message(request->message());
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::Flush(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestFlush* /*request*/,
    tendermint::abci::ResponseFlush* /*response*/) {
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::Info(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestInfo* /*request*/,
    tendermint::abci::ResponseInfo* response) {
  auto info = execution_engine_.info();
  response->set_data(info.data);
  response->set_version(info.version);
  response->set_app_version(info.app_version);
  response->set_last_block_height(info.last_block_height);
  response->set_last_block_app_hash(make_string(info.last_block_app_hash));
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::CheckTx(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestCheckTx* request,
    tendermint::abci::ResponseCheckTx* response) {
  auto tx = make_bytes(request->tx());
  auto tx_view = charter::schema::bytes_view_t{tx.data(), tx.size()};
  auto check = execution_engine_.check_tx(tx_view);
  response->set_code(check.code);
  response->set_data(make_string(check.data));
  response->set_log(check.log);
  response->set_info(check.info);
  response->set_gas_wanted(check.gas_wanted);
  response->set_gas_used(check.gas_used);
  response->set_codespace(check.codespace);
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::Query(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestQuery* request,
    tendermint::abci::ResponseQuery* response) {
  response->set_code(0);
  response->set_key(request->data());
  response->set_value("query not yet implemented");
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::Commit(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestCommit* /*request*/,
    tendermint::abci::ResponseCommit* response) {
  auto commit = execution_engine_.commit();
  response->set_retain_height(commit.retain_height);
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::InitChain(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestInitChain* /*request*/,
    tendermint::abci::ResponseInitChain* response) {
  auto info = execution_engine_.info();
  response->set_app_hash(make_string(info.last_block_app_hash));
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::ListSnapshots(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestListSnapshots* /*request*/,
    tendermint::abci::ResponseListSnapshots* response) {
  auto snapshots = execution_engine_.list_snapshots();
  for (const auto& snapshot : snapshots) {
    auto* out = response->add_snapshots();
    out->set_height(snapshot.height);
    out->set_format(snapshot.format);
    out->set_chunks(snapshot.chunks);
    out->set_hash(make_string(snapshot.hash));
    out->set_metadata(make_string(snapshot.metadata));
  }
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::OfferSnapshot(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestOfferSnapshot* request,
    tendermint::abci::ResponseOfferSnapshot* response) {
  auto offered = charter::execution::snapshot_descriptor{};
  offered.height = request->snapshot().height();
  offered.format = request->snapshot().format();
  offered.chunks = request->snapshot().chunks();
  offered.hash = make_hash32(request->snapshot().hash());
  offered.metadata = make_bytes(request->snapshot().metadata());

  auto result = execution_engine_.offer_snapshot(
      offered, make_hash32(request->app_hash()));
  response->set_result(map_offer_result(result));
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::LoadSnapshotChunk(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestLoadSnapshotChunk* request,
    tendermint::abci::ResponseLoadSnapshotChunk* response) {
  auto chunk = execution_engine_.load_snapshot_chunk(
      request->height(), request->format(), request->chunk());
  if (chunk) {
    response->set_chunk(make_string(*chunk));
  }
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::ApplySnapshotChunk(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestApplySnapshotChunk* request,
    tendermint::abci::ResponseApplySnapshotChunk* response) {
  auto raw = make_bytes(request->chunk());
  auto raw_view = charter::schema::bytes_view_t{raw.data(), raw.size()};
  auto result = execution_engine_.apply_snapshot_chunk(
      request->index(), raw_view, request->sender());
  response->set_result(map_apply_result(result));
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::PrepareProposal(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestPrepareProposal* request,
    tendermint::abci::ResponsePrepareProposal* response) {
  for (const auto& tx : request->txs()) {
    *response->add_txs() = tx;
  }
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::ProcessProposal(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestProcessProposal* /*request*/,
    tendermint::abci::ResponseProcessProposal* response) {
  response->set_status(
      tendermint::abci::ResponseProcessProposal_ProposalStatus_ACCEPT);
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::ExtendVote(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestExtendVote* /*request*/,
    tendermint::abci::ResponseExtendVote* response) {
  response->set_vote_extension("");
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::VerifyVoteExtension(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestVerifyVoteExtension* /*request*/,
    tendermint::abci::ResponseVerifyVoteExtension* response) {
  response->set_status(
      tendermint::abci::ResponseVerifyVoteExtension_VerifyStatus_ACCEPT);
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::FinalizeBlock(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestFinalizeBlock* request,
    tendermint::abci::ResponseFinalizeBlock* response) {
  auto txs = std::vector<charter::schema::bytes_t>{};
  txs.reserve(request->txs_size());
  for (const auto& tx : request->txs()) {
    txs.push_back(make_bytes(tx));
  }

  auto execution = execution_engine_.finalize_block(request->height(), txs);
  for (const auto& tx_result : execution.tx_results) {
    populate_exec_tx_result(tx_result, response->add_tx_results());
  }
  response->set_app_hash(make_string(execution.app_hash));
  return finish_ok(context);
}

#include <spdlog/spdlog.h>
#include <algorithm>
#include <charter/abci/server.hpp>
#include <iterator>
#include <optional>
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
  using enum charter::execution::offer_snapshot_result;
  switch (result) {
    case accept:
      return tendermint::abci::ResponseOfferSnapshot_Result_ACCEPT;
    case abort:
      return tendermint::abci::ResponseOfferSnapshot_Result_ABORT;
    case reject:
      return tendermint::abci::ResponseOfferSnapshot_Result_REJECT;
    case reject_format:
      return tendermint::abci::ResponseOfferSnapshot_Result_REJECT_FORMAT;
    case reject_sender:
      return tendermint::abci::ResponseOfferSnapshot_Result_REJECT_SENDER;
    case unknown:
    default:
      return tendermint::abci::ResponseOfferSnapshot_Result_UNKNOWN;
  }
}

tendermint::abci::ResponseApplySnapshotChunk_Result map_apply_result(
    charter::execution::apply_snapshot_chunk_result result) {
  using enum charter::execution::apply_snapshot_chunk_result;
  switch (result) {
    case accept:
      return tendermint::abci::ResponseApplySnapshotChunk_Result_ACCEPT;
    case abort:
      return tendermint::abci::ResponseApplySnapshotChunk_Result_ABORT;
    case retry:
      return tendermint::abci::ResponseApplySnapshotChunk_Result_RETRY;
    case retry_snapshot:
      return tendermint::abci::ResponseApplySnapshotChunk_Result_RETRY_SNAPSHOT;
    case reject_snapshot:
      return tendermint::abci::
          ResponseApplySnapshotChunk_Result_REJECT_SNAPSHOT;
    case unknown:
    default:
      return tendermint::abci::ResponseApplySnapshotChunk_Result_UNKNOWN;
  }
}

void populate_exec_tx_result(charter::execution::tx_result& source,
                             tendermint::abci::ExecTxResult* destination) {
  destination->set_code(source.code);
  destination->set_data(make_string(source.data));
  destination->set_log(std::move(source.log));
  destination->set_info(std::move(source.info));
  destination->set_gas_wanted(source.gas_wanted);
  destination->set_gas_used(source.gas_used);
  destination->set_codespace(std::string(source.codespace));

  for (const auto& event : source.events) {
    auto* out_event = destination->add_events();
    out_event->set_type(std::move(event.type));
    for (const auto& attribute : event.attributes) {
      auto* out_attribute = out_event->add_attributes();
      out_attribute->set_key(std::move(attribute.key));
      out_attribute->set_value(std::move(attribute.value));
      out_attribute->set_index(attribute.index);
    }
  }
}

}  // namespace

void reactor::OnDone() {
  delete this;  // ughhh
}

listener::listener(charter::execution::engine& engine)
    : execution_engine_{engine} {}

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
  response->set_data(std:::move(info.data));
  response->set_version(std::move(info.version));
  response->set_app_version(info.app_version);
  response->set_last_block_height(info.last_block_height);
  response->set_last_block_app_hash(make_string(info.last_block_state_root));
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::CheckTx(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestCheckTx* request,
    tendermint::abci::ResponseCheckTx* response) {
  // This is called by the mempool to verify if a transaction
  // can or should be added the mempool.
  auto tx = make_bytes(request->tx());
  auto tx_view = charter::schema::bytes_view_t{tx.data(), tx.size()};
  auto check = execution_engine_.check_tx(tx_view);
  response->set_code(check.code);
  response->set_data(make_string(check.data));
  response->set_log(std::move(check.log));
  response->set_info(std::move(check.info));
  response->set_gas_wanted(check.gas_wanted);
  response->set_gas_used(check.gas_used);
  response->set_codespace(std::move(check.codespace));
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::Query(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestQuery* request,
    tendermint::abci::ResponseQuery* response) {
  auto data = make_bytes(request->data());
  auto query = execution_engine_.query(
      request->path(), charter::schema::bytes_view_t{data.data(), data.size()});
  response->set_code(query.code);
  response->set_log(std::move(query.log));
  response->set_info(std::move(query.info));
  response->set_key(make_string(query.key));
  response->set_value(make_string(query.value));
  response->set_height(query.height);
  response->set_codespace(std::move(query.codespace));
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
  // CometBFT ABCI wire field is named "app_hash", but this is the state root:
  // - consensus agreement on post-state
  // - light-client/state proof verification anchor
  // - snapshot/state sync trust anchor
  // - replay consistency and fork detection checkpoint
  response->set_app_hash(make_string(info.last_block_state_root));
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
  auto offered_hash = try_make_hash32(request->snapshot().hash());
  auto trusted_state_root = try_make_hash32(request->app_hash());

  if (!offered_hash || !trusted_state_root) {
    response->set_result(tendermint::abci::ResponseOfferSnapshot_Result_REJECT);
    return finish_ok(context);
  }

  auto offered = charter::execution::snapshot_descriptor{};
  offered.height = request->snapshot().height();
  offered.format = request->snapshot().format();
  offered.chunks = request->snapshot().chunks();
  offered.hash = *offered_hash;
  offered.metadata = make_bytes(request->snapshot().metadata());

  auto result = execution_engine_.offer_snapshot(offered, *trusted_state_root);
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
  // This is called when the block proposer is about to
  // send a proposal message. This allows the engine
  // to reject choices from the mempool if they are not ready.
  // There is an idea of immediate execution where the engine
  // could execute the transactions here or in process proposal
  // as a way to speed up finalize block.  State should
  // not be mutated before that.
  auto total_size = int64_t{};
  auto max_bytes = request->max_tx_bytes();
  for (auto& tx : request->txs()) {
    auto tx_bytes = make_bytes(tx);
    auto check = execution_engine_.check_tx(
        charter::schema::bytes_view_t{tx_bytes.data(), tx_bytes.size()});
    if (check.code != 0) {
      continue;
    }
    auto next_size = total_size + static_cast<int64_t>(tx.size());
    if (max_bytes > 0 && next_size > max_bytes) {
      break;
    }
    total_size = next_size;
    *response->add_txs() = std::move(tx);
  }
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::ProcessProposal(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestProcessProposal* request,
    tendermint::abci::ResponseProcessProposal* response) {
  // This is called by the validator.  The engine can either
  // reject the entire block or not.
  for (const auto& tx : request->txs()) {
    auto tx_bytes = make_bytes(tx);
    auto tx_result = execution_engine_.process_proposal_tx(
        charter::schema::bytes_view_t{tx_bytes.data(), tx_bytes.size()});
    // As a general rule the engine should accept the proposal and
    // just ignore the invalid part.
    if (tx_result.code != 0) {
      response->set_status(
          tendermint::abci::ResponseProcessProposal_ProposalStatus_REJECT);
      return finish_ok(context);
    }
  }
  response->set_status(
      tendermint::abci::ResponseProcessProposal_ProposalStatus_ACCEPT);
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::ExtendVote(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestExtendVote* /*request*/,
    tendermint::abci::ResponseExtendVote* response) {
  // ExtendVote/VerifyVoteExtension can carry validator-signed custody
  // attestations (risk/compliance/oracle/HSM signals) for later policy
  // decisions and audit trails. Treat suspicious signals as early warning:
  // trigger deterministic on-chain response (for example, degraded mode) via
  // normal tx flow, rather than using vote extensions as a direct halt
  // mechanism; this preserves consensus safety/liveness.
  // ExtendVote and VerifyVoteExtension should not mutate world state.
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
    txs.emplace_back(make_bytes(tx));
  }

  auto execution = execution_engine_.finalize_block(request->height(), txs);
  for (auto& tx_result : execution.tx_results) {
    populate_exec_tx_result(tx_result, response->add_tx_results());
  }

  // ABCI uses "app_hash" naming on the wire; we treat this as the state root.
  response->set_app_hash(make_string(execution.state_root));
  return finish_ok(context);
}

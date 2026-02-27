#include <spdlog/spdlog.h>
#include <algorithm>
#include <charter/abci/server.hpp>
#include <filesystem>
#include <fstream>
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

std::optional<charter::schema::hash32_t> try_make_hash32(
    const std::string& value) {
  if (value.size() == 32) {
    auto hash = charter::schema::hash32_t{};
    std::copy_n(std::begin(value), hash.size(), std::begin(hash));
    return hash;
  }
  auto hex = std::string_view{value};
  if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
    hex.remove_prefix(2);
  }
  if (hex.size() != 64) {
    return std::nullopt;
  }
  auto nibble = [](char c) -> std::optional<uint8_t> {
    if (c >= '0' && c <= '9') {
      return static_cast<uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
      return static_cast<uint8_t>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
      return static_cast<uint8_t>(c - 'A' + 10);
    }
    return std::nullopt;
  };
  auto hash = charter::schema::hash32_t{};
  for (size_t i = 0; i < hash.size(); ++i) {
    auto hi = nibble(hex[2 * i]);
    auto lo = nibble(hex[(2 * i) + 1]);
    if (!hi || !lo) {
      return std::nullopt;
    }
    hash[i] = static_cast<uint8_t>((*hi << 4u) | *lo);
  }
  return hash;
}

}  // namespace

void reactor::OnDone() {}

bool listener::load_backup(const std::string& backup_path) {
  if (backup_path.empty()) {
    return false;
  }
  if (!std::filesystem::exists(backup_path)) {
    spdlog::info("No backup file found at '{}'", backup_path);
    return false;
  }

  auto input = std::ifstream{backup_path, std::ios::binary};
  if (!input.good()) {
    spdlog::error("Failed opening backup file '{}'", backup_path);
    return false;
  }
  auto bytes = std::vector<uint8_t>{std::istreambuf_iterator<char>{input},
                                    std::istreambuf_iterator<char>{}};
  if (bytes.empty()) {
    spdlog::warn("Backup file '{}' is empty", backup_path);
    return false;
  }

  auto error = std::string{};
  auto imported = execution_engine_.import_backup(
      charter::schema::bytes_view_t{bytes.data(), bytes.size()}, error);
  if (!imported) {
    spdlog::error("Failed importing backup '{}': {}", backup_path, error);
    return false;
  }
  spdlog::info("Imported backup from '{}'", backup_path);
  return true;
}

bool listener::persist_backup(const std::string& backup_path) const {
  if (backup_path.empty()) {
    return false;
  }
  auto backup = execution_engine_.export_backup();
  auto output = std::ofstream{backup_path, std::ios::binary | std::ios::trunc};
  if (!output.good()) {
    spdlog::error("Failed opening backup output '{}'", backup_path);
    return false;
  }
  output.write(reinterpret_cast<const char*>(backup.data()), backup.size());
  if (!output.good()) {
    spdlog::error("Failed writing backup output '{}'", backup_path);
    return false;
  }
  spdlog::info("Persisted backup to '{}'", backup_path);
  return true;
}

charter::execution::replay_result listener::replay_history() {
  auto replay = execution_engine_.replay_history();
  if (replay.ok) {
    spdlog::info("History replay complete: txs={}, applied={}, height={}",
                 replay.tx_count, replay.applied_count, replay.last_height);
  } else {
    spdlog::warn("History replay failed: {}", replay.error);
  }
  return replay;
}

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
  auto data = make_bytes(request->data());
  auto query = execution_engine_.query(
      request->path(), charter::schema::bytes_view_t{data.data(), data.size()});
  response->set_code(query.code);
  response->set_log(query.log);
  response->set_info(query.info);
  response->set_key(make_string(query.key));
  response->set_value(make_string(query.value));
  response->set_height(query.height);
  response->set_codespace(query.codespace);
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
  auto offered_hash = try_make_hash32(request->snapshot().hash());
  auto trusted_hash = try_make_hash32(request->app_hash());
  if (!offered_hash || !trusted_hash) {
    response->set_result(tendermint::abci::ResponseOfferSnapshot_Result_REJECT);
    return finish_ok(context);
  }

  auto offered = charter::execution::snapshot_descriptor{};
  offered.height = request->snapshot().height();
  offered.format = request->snapshot().format();
  offered.chunks = request->snapshot().chunks();
  offered.hash = *offered_hash;
  offered.metadata = make_bytes(request->snapshot().metadata());

  auto result = execution_engine_.offer_snapshot(offered, *trusted_hash);
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
  auto total_size = int64_t{};
  auto max_bytes = request->max_tx_bytes();
  for (const auto& tx : request->txs()) {
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
    *response->add_txs() = tx;
  }
  return finish_ok(context);
}

grpc::ServerUnaryReactor* listener::ProcessProposal(
    grpc::CallbackServerContext* context,
    const tendermint::abci::RequestProcessProposal* request,
    tendermint::abci::ResponseProcessProposal* response) {
  for (const auto& tx : request->txs()) {
    auto tx_bytes = make_bytes(tx);
    auto tx_result = execution_engine_.process_proposal_tx(
        charter::schema::bytes_view_t{tx_bytes.data(), tx_bytes.size()});
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

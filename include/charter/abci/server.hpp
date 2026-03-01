#pragma once

#include <tendermint/abci/types.grpc.pb.h>
#include <charter/execution/engine.hpp>
#include <variant>

namespace charter::abci {

/// Per-request reactor holder for callback-style gRPC handling.
struct reactor final : public grpc::ServerUnaryReactor {
  virtual void OnDone() override final;

  std::variant<std::monostate,
               tendermint::abci::RequestEcho,
               tendermint::abci::RequestFlush,
               tendermint::abci::RequestInfo,
               tendermint::abci::RequestCheckTx,
               tendermint::abci::RequestQuery,
               tendermint::abci::RequestCommit,
               tendermint::abci::RequestInitChain,
               tendermint::abci::RequestListSnapshots,
               tendermint::abci::RequestOfferSnapshot,
               tendermint::abci::RequestLoadSnapshotChunk,
               tendermint::abci::RequestApplySnapshotChunk,
               tendermint::abci::RequestPrepareProposal,
               tendermint::abci::RequestProcessProposal,
               tendermint::abci::RequestExtendVote,
               tendermint::abci::RequestVerifyVoteExtension,
               tendermint::abci::RequestFinalizeBlock>
      request;
  std::variant<std::monostate,
               tendermint::abci::ResponseEcho*,
               tendermint::abci::ResponseFlush*,
               tendermint::abci::ResponseInfo*,
               tendermint::abci::ResponseCheckTx*,
               tendermint::abci::ResponseQuery*,
               tendermint::abci::ResponseCommit*,
               tendermint::abci::ResponseInitChain*,
               tendermint::abci::ResponseListSnapshots*,
               tendermint::abci::ResponseOfferSnapshot*,
               tendermint::abci::ResponseLoadSnapshotChunk*,
               tendermint::abci::ResponseApplySnapshotChunk*,
               tendermint::abci::ResponsePrepareProposal*,
               tendermint::abci::ResponseProcessProposal*,
               tendermint::abci::ResponseExtendVote*,
               tendermint::abci::ResponseVerifyVoteExtension*,
               tendermint::abci::ResponseFinalizeBlock*>
      response;
};

/// ABCI callback listener used by CometBFT to drive application execution.
///
/// Quick reference (ABCI++):
/// - Echo/Flush: liveness and flush barriers.
/// - Info/InitChain: handshake and initial app hash exchange.
/// - CheckTx: mempool admission checks; no state mutation.
/// - PrepareProposal: proposer-side tx selection/filtering.
/// - ProcessProposal: validator-side proposal accept/reject decision.
/// - FinalizeBlock: execute block and return tx results + app_hash(state_root).
/// - Commit: persist finalized state.
/// - Snapshot methods: state-sync offer/load/apply lifecycle.
/// - Vote extensions: validator-signed side-channel data; no state mutation.
struct listener final : public tendermint::abci::ABCI::CallbackService {
  /// Bind listener to execution engine instance.
  explicit listener(charter::execution::engine& engine);

  /// Echo request/response passthrough used for connectivity checks.
  virtual grpc::ServerUnaryReactor* Echo(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestEcho* request,
      tendermint::abci::ResponseEcho* response) override final;

  /// Flush barrier for request ordering; no app state changes.
  virtual grpc::ServerUnaryReactor* Flush(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestFlush* request,
      tendermint::abci::ResponseFlush* response) override final;

  /// Return app metadata used during node/app handshake.
  virtual grpc::ServerUnaryReactor* Info(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestInfo* request,
      tendermint::abci::ResponseInfo* response) override final;

  /// Mempool admission check for a single tx (decode/validate only).
  virtual grpc::ServerUnaryReactor* CheckTx(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestCheckTx* request,
      tendermint::abci::ResponseCheckTx* response) override final;

  /// Execute deterministic read query against current committed state.
  virtual grpc::ServerUnaryReactor* Query(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestQuery* request,
      tendermint::abci::ResponseQuery* response) override final;

  /// Persist finalized state after FinalizeBlock.
  virtual grpc::ServerUnaryReactor* Commit(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestCommit* request,
      tendermint::abci::ResponseCommit* response) override final;

  /// Initialize chain/application state at genesis handshake.
  virtual grpc::ServerUnaryReactor* InitChain(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestInitChain* request,
      tendermint::abci::ResponseInitChain* response) override final;

  /// Enumerate locally available snapshots for state sync.
  virtual grpc::ServerUnaryReactor* ListSnapshots(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestListSnapshots* request,
      tendermint::abci::ResponseListSnapshots* response) override final;

  /// Accept/reject offered snapshot metadata before chunk transfer.
  virtual grpc::ServerUnaryReactor* OfferSnapshot(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestOfferSnapshot* request,
      tendermint::abci::ResponseOfferSnapshot* response) override final;

  /// Serve one snapshot chunk to syncing peers.
  virtual grpc::ServerUnaryReactor* LoadSnapshotChunk(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestLoadSnapshotChunk* request,
      tendermint::abci::ResponseLoadSnapshotChunk* response) override final;

  /// Apply one received snapshot chunk during state sync restore.
  virtual grpc::ServerUnaryReactor* ApplySnapshotChunk(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestApplySnapshotChunk* request,
      tendermint::abci::ResponseApplySnapshotChunk* response) override final;

  /// Proposer-side tx list preparation under max-bytes and validity checks.
  virtual grpc::ServerUnaryReactor* PrepareProposal(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestPrepareProposal* request,
      tendermint::abci::ResponsePrepareProposal* response) override final;

  /// Validator-side proposal validation; returns ACCEPT or REJECT.
  virtual grpc::ServerUnaryReactor* ProcessProposal(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestProcessProposal* request,
      tendermint::abci::ResponseProcessProposal* response) override final;

  /// Provide validator vote extension payload (no state mutation).
  virtual grpc::ServerUnaryReactor* ExtendVote(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestExtendVote* request,
      tendermint::abci::ResponseExtendVote* response) override final;

  /// Verify peer vote-extension payload validity.
  virtual grpc::ServerUnaryReactor* VerifyVoteExtension(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestVerifyVoteExtension* request,
      tendermint::abci::ResponseVerifyVoteExtension* response) override final;

  /// Execute ordered block transactions and return tx results + app_hash.
  virtual grpc::ServerUnaryReactor* FinalizeBlock(
      grpc::CallbackServerContext* context,
      const tendermint::abci::RequestFinalizeBlock* request,
      tendermint::abci::ResponseFinalizeBlock* response) override final;

  /// Backing execution engine implementing deterministic state machine rules.
  charter::execution::engine& execution_engine_;
};

}  // namespace charter::abci

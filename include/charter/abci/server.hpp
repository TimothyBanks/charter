#pragma once

#include <tendermint/abci/types.grpc.pb.h>
#include <variant>

namespace charter::abci {

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

struct listener final : public tendermint::abci::ABCI::CallbackService {
  virtual grpc::ServerUnaryReactor* Echo(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestEcho* /*request*/,
      tendermint::abci::ResponseEcho* /*response*/) override final;

  virtual grpc::ServerUnaryReactor* Flush(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestFlush* /*request*/,
      tendermint::abci::ResponseFlush* /*response*/) override final;

  virtual grpc::ServerUnaryReactor* Info(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestInfo* /*request*/,
      tendermint::abci::ResponseInfo* /*response*/) override final;

  virtual grpc::ServerUnaryReactor* CheckTx(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestCheckTx* /*request*/,
      tendermint::abci::ResponseCheckTx* /*response*/) override final;

  virtual grpc::ServerUnaryReactor* Query(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestQuery* /*request*/,
      tendermint::abci::ResponseQuery* /*response*/) override final;

  virtual grpc::ServerUnaryReactor* Commit(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestCommit* /*request*/,
      tendermint::abci::ResponseCommit* /*response*/) override final;

  virtual grpc::ServerUnaryReactor* InitChain(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestInitChain* /*request*/,
      tendermint::abci::ResponseInitChain* /*response*/) override final;

  virtual grpc::ServerUnaryReactor* ListSnapshots(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestListSnapshots* /*request*/,
      tendermint::abci::ResponseListSnapshots* /*response*/) override final;

  virtual grpc::ServerUnaryReactor* OfferSnapshot(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestOfferSnapshot* /*request*/,
      tendermint::abci::ResponseOfferSnapshot* /*response*/) override final;

  virtual grpc::ServerUnaryReactor* LoadSnapshotChunk(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestLoadSnapshotChunk* /*request*/,
      tendermint::abci::ResponseLoadSnapshotChunk* /*response*/) override final;

  virtual grpc::ServerUnaryReactor* ApplySnapshotChunk(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestApplySnapshotChunk* /*request*/,
      tendermint::abci::ResponseApplySnapshotChunk* /*response*/)
      override final;

  virtual grpc::ServerUnaryReactor* PrepareProposal(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestPrepareProposal* /*request*/,
      tendermint::abci::ResponsePrepareProposal* /*response*/) override final;

  virtual grpc::ServerUnaryReactor* ProcessProposal(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestProcessProposal* /*request*/,
      tendermint::abci::ResponseProcessProposal* /*response*/) override final;

  virtual grpc::ServerUnaryReactor* ExtendVote(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestExtendVote* /*request*/,
      tendermint::abci::ResponseExtendVote* /*response*/) override final;

  virtual grpc::ServerUnaryReactor* VerifyVoteExtension(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestVerifyVoteExtension* /*request*/,
      tendermint::abci::ResponseVerifyVoteExtension* /*response*/)
      override final;

  virtual grpc::ServerUnaryReactor* FinalizeBlock(
      grpc::CallbackServerContext* /*context*/,
      const tendermint::abci::RequestFinalizeBlock* /*request*/,
      tendermint::abci::ResponseFinalizeBlock* /*response*/) override final;
};

}  // namespace charter::abci
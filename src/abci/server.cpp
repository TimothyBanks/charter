#include <charter/abci/server.hpp>

using namespace charter::abci;

void reactor::OnDone() {}

grpc::ServerUnaryReactor* listener::Echo(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestEcho* /*request*/,
    tendermint::abci::ResponseEcho* /*response*/) {
  return nullptr;
}

grpc::ServerUnaryReactor* listener::Flush(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestFlush* /*request*/,
    tendermint::abci::ResponseFlush* /*response*/) {
  return nullptr;
}

grpc::ServerUnaryReactor* listener::Info(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestInfo* /*request*/,
    tendermint::abci::ResponseInfo* /*response*/) {
  return nullptr;
}

grpc::ServerUnaryReactor* listener::CheckTx(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestCheckTx* /*request*/,
    tendermint::abci::ResponseCheckTx* /*response*/) {
  return nullptr;
}

grpc::ServerUnaryReactor* listener::Query(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestQuery* /*request*/,
    tendermint::abci::ResponseQuery* /*response*/) {
  return nullptr;
}

grpc::ServerUnaryReactor* listener::Commit(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestCommit* /*request*/,
    tendermint::abci::ResponseCommit* /*response*/) {
  return nullptr;
}

grpc::ServerUnaryReactor* listener::InitChain(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestInitChain* /*request*/,
    tendermint::abci::ResponseInitChain* /*response*/) {
  return nullptr;
}

grpc::ServerUnaryReactor* listener::ListSnapshots(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestListSnapshots* /*request*/,
    tendermint::abci::ResponseListSnapshots* /*response*/) {
  return nullptr;
}

grpc::ServerUnaryReactor* listener::OfferSnapshot(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestOfferSnapshot* /*request*/,
    tendermint::abci::ResponseOfferSnapshot* /*response*/) {
  return nullptr;
}

grpc::ServerUnaryReactor* listener::LoadSnapshotChunk(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestLoadSnapshotChunk* /*request*/,
    tendermint::abci::ResponseLoadSnapshotChunk* /*response*/) {
  return nullptr;
}

grpc::ServerUnaryReactor* listener::ApplySnapshotChunk(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestApplySnapshotChunk* /*request*/,
    tendermint::abci::ResponseApplySnapshotChunk* /*response*/) {
  return nullptr;
}

grpc::ServerUnaryReactor* listener::PrepareProposal(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestPrepareProposal* /*request*/,
    tendermint::abci::ResponsePrepareProposal* /*response*/) {
  return nullptr;
}

grpc::ServerUnaryReactor* listener::ProcessProposal(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestProcessProposal* /*request*/,
    tendermint::abci::ResponseProcessProposal* /*response*/) {
  return nullptr;
}

grpc::ServerUnaryReactor* listener::ExtendVote(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestExtendVote* /*request*/,
    tendermint::abci::ResponseExtendVote* /*response*/) {
  return nullptr;
}

grpc::ServerUnaryReactor* listener::VerifyVoteExtension(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestVerifyVoteExtension* /*request*/,
    tendermint::abci::ResponseVerifyVoteExtension* /*response*/) {
  return nullptr;
}

grpc::ServerUnaryReactor* listener::FinalizeBlock(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestFinalizeBlock* /*request*/,
    tendermint::abci::ResponseFinalizeBlock* /*response*/) {
  return nullptr;
}
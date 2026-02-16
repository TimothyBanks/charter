#include <spdlog/spdlog.h>
#include <charter/abci/server.hpp>

using namespace charter::abci;

void reactor::OnDone() {}

grpc::ServerUnaryReactor* listener::Echo(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestEcho* /*request*/,
    tendermint::abci::ResponseEcho* /*response*/) {
  spdlog::info("Echo endpoint hit...");
  return nullptr;
}

grpc::ServerUnaryReactor* listener::Flush(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestFlush* /*request*/,
    tendermint::abci::ResponseFlush* /*response*/) {
  spdlog::info("Flush endpoint hit...");
  return nullptr;
}

grpc::ServerUnaryReactor* listener::Info(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestInfo* /*request*/,
    tendermint::abci::ResponseInfo* /*response*/) {
  spdlog::info("Info endpoint hit...");
  return nullptr;
}

grpc::ServerUnaryReactor* listener::CheckTx(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestCheckTx* /*request*/,
    tendermint::abci::ResponseCheckTx* /*response*/) {
  spdlog::info("CheckTx endpoint hit...");
  return nullptr;
}

grpc::ServerUnaryReactor* listener::Query(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestQuery* /*request*/,
    tendermint::abci::ResponseQuery* /*response*/) {
  spdlog::info("Query endpoint hit...");
  return nullptr;
}

grpc::ServerUnaryReactor* listener::Commit(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestCommit* /*request*/,
    tendermint::abci::ResponseCommit* /*response*/) {
  spdlog::info("Commit endpoint hit...");
  return nullptr;
}

grpc::ServerUnaryReactor* listener::InitChain(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestInitChain* /*request*/,
    tendermint::abci::ResponseInitChain* /*response*/) {
  spdlog::info("InitChain endpoint hit...");
  return nullptr;
}

grpc::ServerUnaryReactor* listener::ListSnapshots(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestListSnapshots* /*request*/,
    tendermint::abci::ResponseListSnapshots* /*response*/) {
  spdlog::info("ListSnapshots endpoint hit...");
  return nullptr;
}

grpc::ServerUnaryReactor* listener::OfferSnapshot(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestOfferSnapshot* /*request*/,
    tendermint::abci::ResponseOfferSnapshot* /*response*/) {
  spdlog::info("OfferSnapshot endpoint hit...");
  return nullptr;
}

grpc::ServerUnaryReactor* listener::LoadSnapshotChunk(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestLoadSnapshotChunk* /*request*/,
    tendermint::abci::ResponseLoadSnapshotChunk* /*response*/) {
  spdlog::info("LoadSnapshotChunk endpoint hit...");
  return nullptr;
}

grpc::ServerUnaryReactor* listener::ApplySnapshotChunk(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestApplySnapshotChunk* /*request*/,
    tendermint::abci::ResponseApplySnapshotChunk* /*response*/) {
  spdlog::info("ApplySnapshotChunk endpoint hit...");
  return nullptr;
}

grpc::ServerUnaryReactor* listener::PrepareProposal(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestPrepareProposal* /*request*/,
    tendermint::abci::ResponsePrepareProposal* /*response*/) {
  spdlog::info("PrepareProposal endpoint hit...");
  return nullptr;
}

grpc::ServerUnaryReactor* listener::ProcessProposal(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestProcessProposal* /*request*/,
    tendermint::abci::ResponseProcessProposal* /*response*/) {
  spdlog::info("ProcessProposal endpoint hit...");
  return nullptr;
}

grpc::ServerUnaryReactor* listener::ExtendVote(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestExtendVote* /*request*/,
    tendermint::abci::ResponseExtendVote* /*response*/) {
  spdlog::info("ExtendVote endpoint hit...");
  return nullptr;
}

grpc::ServerUnaryReactor* listener::VerifyVoteExtension(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestVerifyVoteExtension* /*request*/,
    tendermint::abci::ResponseVerifyVoteExtension* /*response*/) {
  spdlog::info("VerifyVoteExtension endpoint hit...");
  return nullptr;
}

grpc::ServerUnaryReactor* listener::FinalizeBlock(
    grpc::CallbackServerContext* /*context*/,
    const tendermint::abci::RequestFinalizeBlock* /*request*/,
    tendermint::abci::ResponseFinalizeBlock* /*response*/) {
  spdlog::info("FinalizeBlock endpoint hit...");
  return nullptr;
}
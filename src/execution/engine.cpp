#include <spdlog/spdlog.h>
#include <algorithm>
#include <array>
#include <charter/blake3/hash.hpp>
#include <charter/execution/engine.hpp>
#include <charter/schema/encoding/scale/encoder.hpp>
#include <charter/schema/encoding/scale/transaction.hpp>
#include <iterator>
#include <tuple>
#include <utility>

using namespace charter::schema;

namespace {

using encoder_t = charter::schema::encoding::encoder<
    charter::schema::encoding::scale_encoder_tag>;

charter::schema::hash32_t fold_app_hash(const charter::schema::hash32_t& seed,
                                        const charter::schema::bytes_t& tx,
                                        uint64_t height,
                                        uint64_t index) {
  auto material = charter::schema::bytes_t{};
  material.reserve(seed.size() + tx.size() + 32);
  material.insert(std::end(material), std::begin(seed), std::end(seed));
  material.insert(std::end(material), std::begin(tx), std::end(tx));

  auto encoder = encoder_t{};
  auto encoded_suffix = encoder.encode(std::tuple{height, index});
  material.insert(std::end(material), std::begin(encoded_suffix),
                  std::end(encoded_suffix));
  return charter::blake3::hash(
      charter::schema::bytes_view_t{material.data(), material.size()});
}

std::optional<charter::schema::transaction_t> decode_transaction(
    const charter::schema::bytes_view_t& raw_tx,
    std::string& error) {
  if (raw_tx.empty()) {
    error = "empty transaction";
    return std::nullopt;
  }
  try {
    auto encoder = encoder_t{};
    auto tx = charter::schema::transaction_t{};
    tx = encoder.decode<charter::schema::transaction_t>(raw_tx);
    return tx;
  } catch (const std::exception& ex) {
    error = ex.what();
    return std::nullopt;
  }
}

charter::execution::snapshot_descriptor make_snapshot_descriptor(
    uint64_t height,
    const charter::schema::hash32_t& app_hash) {
  auto metadata =
      charter::schema::make_bytes(std::string_view{"charter-snapshot-v1"});

  auto hash_material = charter::schema::bytes_t{};
  hash_material.reserve(app_hash.size() + metadata.size() + 16);
  hash_material.insert(std::end(hash_material), std::begin(app_hash),
                       std::end(app_hash));
  hash_material.insert(std::end(hash_material), std::begin(metadata),
                       std::end(metadata));

  auto encoder = encoder_t{};
  auto encoded_height = encoder.encode(height);
  hash_material.insert(std::end(hash_material), std::begin(encoded_height),
                       std::end(encoded_height));

  auto snapshot = charter::execution::snapshot_descriptor{};
  snapshot.height = height;
  snapshot.format = 1;
  snapshot.chunks = 1;
  snapshot.hash = charter::blake3::hash(charter::schema::bytes_view_t{
      hash_material.data(), hash_material.size()});
  snapshot.metadata = std::move(metadata);
  return snapshot;
}

}  // namespace

namespace charter::execution {

engine::engine(uint64_t snapshot_interval, std::string db_path)
    : db_path_(std::move(db_path)) {
  auto lock = std::scoped_lock{mutex_};
  spdlog::info("Initializing execution engine with RocksDB path '{}'",
               db_path_);

  storage_ =
      charter::storage::make_storage<charter::storage::rocksdb_storage_tag>(
          db_path_);
  snapshot_interval_ = snapshot_interval;
  load_persisted_state();

  if (last_committed_app_hash_.empty()) {
    last_committed_app_hash_ = make_zero_hash();
    pending_app_hash_ = last_committed_app_hash_;
    storage_.save_committed_state(charter::storage::committed_state{
        .height = last_committed_height_,
        .app_hash = last_committed_app_hash_});
  }
  if (snapshot_interval_ == 0) {
    spdlog::warn("Snapshot interval is 0; snapshots disabled");
  }
  spdlog::info("Execution engine ready at height {} with {} snapshot(s)",
               last_committed_height_, snapshots_.size());
}

tx_result engine::check_tx(const charter::schema::bytes_view_t& raw_tx) const {
  auto result = tx_result{};
  auto decode_error = std::string{};
  auto maybe_tx = decode_transaction(
      charter::schema::bytes_view_t{raw_tx.data(), raw_tx.size()},
      decode_error);
  if (!maybe_tx) {
    result.code = 1;
    result.log = "invalid transaction";
    result.info = decode_error;
    result.codespace = "charter.checktx";
    return result;
  }
  if (maybe_tx->version != 1) {
    result.code = 2;
    result.log = "unsupported transaction version";
    result.info = "expected version 1";
    result.codespace = "charter.checktx";
    return result;
  }
  result.code = 0;
  result.gas_wanted = 1000;
  return result;
}

tx_result engine::execute_operation(
    const charter::schema::transaction_t& tx) const {
  auto result = tx_result{};
  std::visit(
      overloaded{
          [&](const charter::schema::create_workspace_t&) {
            result.info = "create_workspace accepted";
          },
          [&](const charter::schema::create_vault_t&) {
            result.info = "create_vault accepted";
          },
          [&](const charter::schema::create_policy_set_t&) {
            result.info = "create_policy_set accepted";
          },
          [&](const charter::schema::activate_policy_set_t&) {
            result.info = "activate_policy_set accepted";
          },
          [&](const charter::schema::propose_intent_t&) {
            result.info = "propose_intent accepted";
          },
          [&](const charter::schema::approve_intent_t&) {
            result.info = "approve_intent accepted";
          },
          [&](const charter::schema::cancel_intent_t&) {
            result.info = "cancel_intent accepted";
          },
          [&](const charter::schema::execute_intent_t&) {
            result.info = "execute_intent accepted";
          },
          [&](const charter::schema::upsert_attestation_t&) {
            result.info = "upsert_attestation accepted";
          },
          [&](const charter::schema::revoke_attestation_t&) {
            result.info = "revoke_attestation accepted";
          }},
      tx.payload);

  if (result.code == 0) {
    result.gas_wanted = 1000;
    result.gas_used = 750;
  }
  return result;
}

block_result engine::finalize_block(
    uint64_t height,
    const std::vector<charter::schema::bytes_t>& txs) {
  auto lock = std::scoped_lock{mutex_};
  auto result = block_result{};
  result.tx_results.reserve(txs.size());

  auto rolling_hash = last_committed_app_hash_;
  for (size_t i = 0; i < txs.size(); ++i) {
    auto decode_error = std::string{};
    auto maybe_tx = decode_transaction(
        charter::schema::bytes_view_t{txs[i].data(), txs[i].size()},
        decode_error);
    if (!maybe_tx) {
      auto tx_result = execution::tx_result{};
      tx_result.code = 1;
      tx_result.log = "invalid transaction";
      tx_result.info = decode_error;
      tx_result.codespace = "charter.finalize";
      result.tx_results.push_back(std::move(tx_result));
      continue;
    }
    auto tx_result = execute_operation(*maybe_tx);
    result.tx_results.push_back(tx_result);
    if (tx_result.code == 0) {
      rolling_hash = fold_app_hash(rolling_hash, txs[i], height, i);
    }
  }

  pending_height_ = static_cast<int64_t>(height);
  pending_app_hash_ = rolling_hash;
  result.app_hash = rolling_hash;
  return result;
}

commit_result engine::commit() {
  auto lock = std::scoped_lock{mutex_};
  if (pending_height_ > 0) {
    last_committed_height_ = pending_height_;
    last_committed_app_hash_ = pending_app_hash_;
    pending_height_ = 0;
  }

  create_snapshot_if_due(last_committed_height_);
  storage_.save_committed_state(charter::storage::committed_state{
      .height = last_committed_height_, .app_hash = last_committed_app_hash_});

  auto result = commit_result{};
  result.retain_height = 0;
  result.committed_height = last_committed_height_;
  result.app_hash = last_committed_app_hash_;
  return result;
}

app_info engine::info() const {
  auto lock = std::scoped_lock{mutex_};
  auto result = app_info{};
  result.last_block_height = last_committed_height_;
  result.last_block_app_hash = last_committed_app_hash_;
  return result;
}

std::vector<snapshot_descriptor> engine::list_snapshots() const {
  auto lock = std::scoped_lock{mutex_};
  return snapshots_;
}

std::optional<charter::schema::bytes_t> engine::load_snapshot_chunk(
    uint64_t height,
    uint32_t format,
    uint32_t chunk) const {
  auto lock = std::scoped_lock{mutex_};
  auto loaded = storage_.load_snapshot_chunk(height, format, chunk);
  if (!loaded) {
    spdlog::warn("Snapshot chunk not found: h={}, f={}, c={}", height, format,
                 chunk);
  }
  return loaded;
}

offer_snapshot_result engine::offer_snapshot(
    const snapshot_descriptor& offered,
    const charter::schema::hash32_t& trusted_app_hash) const {
  if (offered.format != 1) {
    spdlog::warn("Rejecting snapshot offer with unsupported format {}",
                 offered.format);
    return offer_snapshot_result::reject_format;
  }
  if (!trusted_app_hash.empty() && trusted_app_hash != offered.hash) {
    spdlog::warn("Rejecting snapshot offer at height {} due to hash mismatch",
                 offered.height);
    return offer_snapshot_result::reject;
  }
  return offer_snapshot_result::accept;
}

apply_snapshot_chunk_result engine::apply_snapshot_chunk(
    uint32_t index,
    const charter::schema::bytes_view_t& chunk,
    const std::string& sender) {
  (void)sender;
  if (index != 0 || chunk.empty()) {
    return apply_snapshot_chunk_result::retry_snapshot;
  }

  auto lock = std::scoped_lock{mutex_};
  last_committed_app_hash_ = charter::blake3::hash(
      charter::schema::bytes_view_t{chunk.data(), chunk.size()});
  storage_.save_committed_state(charter::storage::committed_state{
      .height = last_committed_height_, .app_hash = last_committed_app_hash_});
  spdlog::info("Applied snapshot chunk {}", index);
  return apply_snapshot_chunk_result::accept;
}

void engine::create_snapshot_if_due(int64_t height) {
  if (snapshot_interval_ == 0 || height <= 0 ||
      (height % static_cast<int64_t>(snapshot_interval_)) != 0) {
    return;
  }

  auto chunk = last_committed_app_hash_;
  auto snapshot =
      make_snapshot_descriptor(static_cast<uint64_t>(height), chunk);
  storage_.save_snapshot(
      charter::storage::snapshot_descriptor{.height = snapshot.height,
                                            .format = snapshot.format,
                                            .chunks = snapshot.chunks,
                                            .hash = snapshot.hash,
                                            .metadata = snapshot.metadata},
      chunk);

  auto existing = std::find_if(std::begin(snapshots_), std::end(snapshots_),
                               [&](const snapshot_descriptor& value) {
                                 return value.height == snapshot.height &&
                                        value.format == snapshot.format;
                               });
  if (existing == std::end(snapshots_)) {
    snapshots_.push_back(snapshot);
  } else {
    *existing = snapshot;
  }
  spdlog::info("Created snapshot at height {} format {}", snapshot.height,
               snapshot.format);
}

void engine::load_persisted_state() {
  spdlog::debug("Loading persisted engine state");
  if (auto committed = storage_.load_committed_state()) {
    last_committed_height_ = committed->height;
    last_committed_app_hash_ = committed->app_hash;
    pending_app_hash_ = committed->app_hash;
  }

  auto stored_snapshots = storage_.list_snapshots();
  snapshots_.clear();
  snapshots_.reserve(stored_snapshots.size());
  for (const auto& snapshot : stored_snapshots) {
    snapshots_.push_back(snapshot_descriptor{.height = snapshot.height,
                                             .format = snapshot.format,
                                             .chunks = snapshot.chunks,
                                             .hash = snapshot.hash,
                                             .metadata = snapshot.metadata});
  }
}

}  // namespace charter::execution

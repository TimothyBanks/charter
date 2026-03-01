#pragma once

#include <charter/execution/signature_verifier.hpp>
#include <charter/schema/app_info.hpp>
#include <charter/schema/apply_snapshot_chunk_result.hpp>
#include <charter/schema/block_result.hpp>
#include <charter/schema/commit_result.hpp>
#include <charter/schema/encoding/encoder.hpp>
#include <charter/schema/history_entry.hpp>
#include <charter/schema/offer_snapshot_result.hpp>
#include <charter/schema/primitives.hpp>
#include <charter/schema/query_result.hpp>
#include <charter/schema/replay_result.hpp>
#include <charter/schema/snapshot_descriptor.hpp>
#include <charter/schema/transaction.hpp>
#include <charter/schema/transaction_error_code.hpp>
#include <charter/schema/transaction_event.hpp>
#include <charter/schema/transaction_event_attribute.hpp>
#include <charter/schema/transaction_result.hpp>
#include <charter/storage/rocksdb/storage.hpp>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace charter::execution {

/// Deterministic custody state machine used by the ABCI server.
///
/// The engine validates transactions, executes payload operations, persists
/// state/history/security events, and exposes query/snapshot/backup interfaces.
class engine final {
 public:
  /// Construct the engine with encoder/storage backends and runtime options.
  ///
  /// `snapshot_interval` controls periodic snapshot creation in commit flow.
  /// `require_strict_crypto` enables real signature verification; when false,
  /// signatures are bypassed for PoC compatibility mode.
  explicit engine(
      charter::schema::encoding::encoder<
          charter::schema::encoding::scale_encoder_tag>& encoder,
      charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
      uint64_t snapshot_interval = 100,
      bool require_strict_crypto = true);

  /// Admit a transaction for mempool inclusion (CheckTx semantics).
  ///
  /// Performs decode + validation checks only; does not mutate application
  /// state.
  charter::schema::transaction_result_t check_transaction(
      const charter::schema::bytes_view_t& raw_tx);

  /// Validate a transaction in proposal building flow (PrepareProposal path).
  ///
  /// Reuses the same validation pipeline as CheckTx.
  charter::schema::transaction_result_t process_proposal_transaction(
      const charter::schema::bytes_view_t& raw_tx);

  /// Execute a candidate block and compute its resulting state_root.
  ///
  /// Transactions are processed in-order; per-tx results are returned even on
  /// failures.
  charter::schema::block_result_t finalize_block(
      uint64_t height,
      const std::vector<charter::schema::bytes_t>& txs);

  /// Commit the latest finalized block state to durable storage.
  ///
  /// Persists committed height/state_root and triggers snapshot creation when
  /// due.
  charter::schema::commit_result_t commit();

  /// Return application metadata (latest committed height and state_root).
  charter::schema::app_info_t info() const;

  /// Execute a deterministic read-path query by route.
  charter::schema::query_result_t query(
      std::string_view path,
      const charter::schema::bytes_view_t& data);

  /// Return history entries in the inclusive height range.
  std::vector<charter::schema::history_entry_t> history(
      uint64_t from_height,
      uint64_t to_height) const;

  /// Export backup bytes to filesystem path.
  bool export_backup(std::string_view backup_path) const;

  /// Export backup bytes as in-memory payload.
  charter::schema::bytes_t export_backup() const;

  /// Load backup bytes from filesystem path and replace in-memory state.
  bool load_backup(std::string_view backup_path);

  /// Load backup bytes from memory and replace in-memory state.
  ///
  /// On failure, `error` contains a human-readable reason.
  bool load_backup(const charter::schema::bytes_view_t& backup,
                   std::string& error);

  /// Re-run persisted history and check deterministic state-root agreement.
  charter::schema::replay_result_t replay_history();

  /// Install runtime signature verifier callback.
  ///
  /// Ignored when strict-crypto mode is disabled.
  void set_signature_verifier(signature_verifier_t verifier);

  /// List persisted local snapshots.
  std::vector<charter::schema::snapshot_descriptor_t> list_snapshots() const;

  /// Load a specific snapshot chunk.
  std::optional<charter::schema::bytes_t>
  load_snapshot_chunk(uint64_t height, uint32_t format, uint32_t chunk) const;

  /// Evaluate offered snapshot compatibility against trusted state root.
  charter::schema::offer_snapshot_result offer_snapshot(
      const charter::schema::snapshot_descriptor_t& offered,
      const charter::schema::hash32_t& trusted_state_root);

  /// Apply one snapshot chunk for previously accepted offer.
  charter::schema::apply_snapshot_chunk_result apply_snapshot_chunk(
      uint32_t index,
      const charter::schema::bytes_view_t& chunk,
      const std::string& sender);

 private:
  /// Execute a validated transaction payload and return execution result.
  charter::schema::transaction_result_t execute_operation(
      const charter::schema::transaction_t& tx);

  /// Validate transaction envelope, authorization, signature, and nonce.
  ///
  /// When `expected_nonce` is provided, it is used instead of storage nonce
  /// (used by block-local sequencing during FinalizeBlock).
  charter::schema::transaction_result_t validate_transaction(
      const charter::schema::transaction_t& tx,
      std::string_view codespace,
      std::optional<uint64_t> expected_nonce);

  /// Create/persist a snapshot if the configured interval has elapsed.
  void create_snapshot_if_due(int64_t height);
  /// Load committed state and snapshots from storage at startup.
  void load_persisted_state();

  mutable std::mutex mutex_;
  charter::schema::encoding::encoder<
      charter::schema::encoding::scale_encoder_tag>& encoder_;
  charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage_;
  int64_t last_committed_height_{};
  charter::schema::hash32_t last_committed_state_root_;
  int64_t pending_height_{};
  charter::schema::hash32_t pending_state_root_;
  uint64_t current_block_time_ms_{};
  uint64_t current_block_height_{};
  charter::schema::hash32_t chain_id_;
  bool require_strict_crypto_{true};
  bool signature_verifier_overridden_{false};
  signature_verifier_t signature_verifier_;
  std::optional<charter::schema::snapshot_descriptor_t> pending_snapshot_offer_;
  std::vector<charter::schema::snapshot_descriptor_t> snapshots_;
  uint64_t snapshot_interval_{100};
};

}  // namespace charter::execution

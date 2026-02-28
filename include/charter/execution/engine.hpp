#pragma once

#include <charter/execution/app_info.hpp>
#include <charter/execution/apply_snapshot_chunk_result.hpp>
#include <charter/execution/block_result.hpp>
#include <charter/execution/commit_result.hpp>
#include <charter/execution/history_entry.hpp>
#include <charter/execution/offer_snapshot_result.hpp>
#include <charter/execution/query_result.hpp>
#include <charter/execution/replay_result.hpp>
#include <charter/execution/signature_verifier.hpp>
#include <charter/execution/snapshot_descriptor.hpp>
#include <charter/execution/tx_result.hpp>
#include <charter/schema/primitives.hpp>
#include <charter/schema/transaction.hpp>
#include <charter/storage/rocksdb/storage.hpp>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace charter::execution {

class engine final {
 public:
  explicit engine(uint64_t snapshot_interval = 100,
                  std::string db_path = "charter.db",
                  bool require_strict_crypto = true);

  tx_result check_tx(const charter::schema::bytes_view_t& raw_tx);
  tx_result process_proposal_tx(const charter::schema::bytes_view_t& raw_tx);
  block_result finalize_block(uint64_t height,
                              const std::vector<charter::schema::bytes_t>& txs);
  commit_result commit();
  app_info info() const;
  query_result query(std::string_view path,
                     const charter::schema::bytes_view_t& data);
  std::vector<history_entry> history(uint64_t from_height,
                                     uint64_t to_height) const;

  bool export_backup(std::string_view backup_path) const;
  charter::schema::bytes_t export_backup() const;

  bool load_backup(std::string_view backup_path);
  bool load_backup(const charter::schema::bytes_view_t& backup,
                   std::string& error);

  replay_result replay_history();
  void set_signature_verifier(signature_verifier_t verifier);

  std::vector<snapshot_descriptor> list_snapshots() const;
  std::optional<charter::schema::bytes_t>
  load_snapshot_chunk(uint64_t height, uint32_t format, uint32_t chunk) const;
  offer_snapshot_result offer_snapshot(
      const snapshot_descriptor& offered,
      const charter::schema::hash32_t& trusted_state_root);
  apply_snapshot_chunk_result apply_snapshot_chunk(
      uint32_t index,
      const charter::schema::bytes_view_t& chunk,
      const std::string& sender);

 private:
  tx_result execute_operation(const charter::schema::transaction_t& tx);
  tx_result validate_tx(const charter::schema::transaction_t& tx,
                        std::string_view codespace,
                        std::optional<uint64_t> expected_nonce);
  void create_snapshot_if_due(int64_t height);
  void load_persisted_state();

  mutable std::mutex mutex_;
  charter::storage::storage<charter::storage::rocksdb_storage_tag> storage_;
  std::string db_path_;
  int64_t last_committed_height_{};
  charter::schema::hash32_t last_committed_state_root_;
  int64_t pending_height_{};
  charter::schema::hash32_t pending_state_root_;
  uint64_t current_block_time_ms_{};
  uint64_t current_block_height_{};
  charter::schema::hash32_t chain_id_;
  signature_verifier_t signature_verifier_;
  std::optional<snapshot_descriptor> pending_snapshot_offer_;
  std::vector<snapshot_descriptor> snapshots_;
  uint64_t snapshot_interval_{100};
};

}  // namespace charter::execution

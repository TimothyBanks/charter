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

class engine final {
 public:
  explicit engine(
      charter::schema::encoding::encoder<
          charter::schema::encoding::scale_encoder_tag>& encoder,
      charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage,
      uint64_t snapshot_interval = 100,
      bool require_strict_crypto = true);

  charter::schema::transaction_result_t check_transaction(
      const charter::schema::bytes_view_t& raw_tx);
  charter::schema::transaction_result_t process_proposal_transaction(
      const charter::schema::bytes_view_t& raw_tx);
  charter::schema::block_result_t finalize_block(
      uint64_t height,
      const std::vector<charter::schema::bytes_t>& txs);
  charter::schema::commit_result_t commit();
  charter::schema::app_info_t info() const;
  charter::schema::query_result_t query(
      std::string_view path,
      const charter::schema::bytes_view_t& data);
  std::vector<charter::schema::history_entry_t> history(
      uint64_t from_height,
      uint64_t to_height) const;

  bool export_backup(std::string_view backup_path) const;
  charter::schema::bytes_t export_backup() const;

  bool load_backup(std::string_view backup_path);
  bool load_backup(const charter::schema::bytes_view_t& backup,
                   std::string& error);

  charter::schema::replay_result_t replay_history();
  void set_signature_verifier(signature_verifier_t verifier);

  std::vector<charter::schema::snapshot_descriptor_t> list_snapshots() const;
  std::optional<charter::schema::bytes_t>
  load_snapshot_chunk(uint64_t height, uint32_t format, uint32_t chunk) const;
  charter::schema::offer_snapshot_result offer_snapshot(
      const charter::schema::snapshot_descriptor_t& offered,
      const charter::schema::hash32_t& trusted_state_root);
  charter::schema::apply_snapshot_chunk_result apply_snapshot_chunk(
      uint32_t index,
      const charter::schema::bytes_view_t& chunk,
      const std::string& sender);

 private:
  charter::schema::transaction_result_t execute_operation(
      const charter::schema::transaction_t& tx);
  charter::schema::transaction_result_t validate_transaction(
      const charter::schema::transaction_t& tx,
      std::string_view codespace,
      std::optional<uint64_t> expected_nonce);
  void create_snapshot_if_due(int64_t height);
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
  signature_verifier_t signature_verifier_;
  std::optional<charter::schema::snapshot_descriptor_t> pending_snapshot_offer_;
  std::vector<charter::schema::snapshot_descriptor_t> snapshots_;
  uint64_t snapshot_interval_{100};
};

}  // namespace charter::execution

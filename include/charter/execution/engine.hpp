#pragma once

#include <charter/schema/primitives.hpp>
#include <charter/schema/transaction.hpp>
#include <charter/storage/rocksdb/storage.hpp>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace charter::execution {

struct tx_result final {
  uint32_t code{};
  charter::schema::bytes_t data;
  std::string log;
  std::string info;
  int64_t gas_wanted{};
  int64_t gas_used{};
  std::string codespace;
};

struct block_result final {
  std::vector<tx_result> tx_results;
  charter::schema::hash32_t app_hash;
};

struct commit_result final {
  int64_t retain_height{};
  int64_t committed_height{};
  charter::schema::hash32_t app_hash;
};

struct app_info final {
  std::string data{"charter-custody"};
  std::string version{"0.1.0-poc"};
  uint64_t app_version{1};
  int64_t last_block_height{};
  charter::schema::hash32_t last_block_app_hash;
};

struct snapshot_descriptor final {
  uint64_t height{};
  uint32_t format{1};
  uint32_t chunks{1};
  charter::schema::hash32_t hash;
  charter::schema::bytes_t metadata;
};

enum class offer_snapshot_result : uint8_t {
  unknown = 0,
  accept = 1,
  abort = 2,
  reject = 3,
  reject_format = 4,
  reject_sender = 5,
};

enum class apply_snapshot_chunk_result : uint8_t {
  unknown = 0,
  accept = 1,
  abort = 2,
  retry = 3,
  retry_snapshot = 4,
  reject_snapshot = 5,
};

class engine final {
 public:
  explicit engine(uint64_t snapshot_interval = 100,
                  std::string db_path = "charter.db");

  tx_result check_tx(const charter::schema::bytes_view_t& raw_tx) const;
  block_result finalize_block(uint64_t height,
                              const std::vector<charter::schema::bytes_t>& txs);
  commit_result commit();
  app_info info() const;

  std::vector<snapshot_descriptor> list_snapshots() const;
  std::optional<charter::schema::bytes_t>
  load_snapshot_chunk(uint64_t height, uint32_t format, uint32_t chunk) const;
  offer_snapshot_result offer_snapshot(
      const snapshot_descriptor& offered,
      const charter::schema::hash32_t& trusted_app_hash) const;
  apply_snapshot_chunk_result apply_snapshot_chunk(
      uint32_t index,
      const charter::schema::bytes_view_t& chunk,
      const std::string& sender);

 private:
  tx_result execute_operation(const charter::schema::transaction_t& tx) const;
  void create_snapshot_if_due(int64_t height);
  void load_persisted_state();

  mutable std::mutex mutex_;
  charter::storage::storage<charter::storage::rocksdb_storage_tag> storage_;
  std::string db_path_;
  int64_t last_committed_height_{};
  charter::schema::hash32_t last_committed_app_hash_;
  int64_t pending_height_{};
  charter::schema::hash32_t pending_app_hash_;
  std::vector<snapshot_descriptor> snapshots_;
  uint64_t snapshot_interval_{100};
};

}  // namespace charter::execution

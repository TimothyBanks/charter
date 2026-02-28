#pragma once

#include <charter/schema/primitives.hpp>
#include <charter/schema/transaction.hpp>
#include <charter/storage/rocksdb/storage.hpp>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace charter::execution {

struct tx_event_attribute final {
  std::string key;
  std::string value;
  bool index{};
};

struct tx_event final {
  std::string type;
  std::vector<tx_event_attribute> attributes;
};

struct tx_result final {
  uint32_t code{};
  charter::schema::bytes_t data;
  std::string log;
  std::string info;
  int64_t gas_wanted{};
  int64_t gas_used{};
  std::string codespace;
  std::vector<tx_event> events;
};

struct block_result final {
  std::vector<tx_result> tx_results;
  charter::schema::hash32_t state_root;
};

struct commit_result final {
  int64_t retain_height{};
  int64_t committed_height{};
  charter::schema::hash32_t state_root;
};

struct app_info final {
  std::string data{"charter-custody"};
  std::string version{"0.1.0-poc"};
  uint64_t app_version{1};
  int64_t last_block_height{};
  charter::schema::hash32_t last_block_state_root;
};

struct query_result final {
  uint32_t code{};
  std::string log;
  std::string info;
  charter::schema::bytes_t key;
  charter::schema::bytes_t value;
  int64_t height{};
  std::string codespace;
};

struct history_entry final {
  uint64_t height{};
  uint32_t index{};
  uint32_t code{};
  charter::schema::bytes_t tx;
};

struct replay_result final {
  bool ok{};
  uint64_t tx_count{};
  uint64_t applied_count{};
  int64_t last_height{};
  charter::schema::hash32_t state_root;
  std::string error;
};

using signature_verifier_t =
    std::function<bool(const charter::schema::bytes_view_t& message,
                       const charter::schema::signer_id_t& signer,
                       const charter::schema::signature_t& signature)>;

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

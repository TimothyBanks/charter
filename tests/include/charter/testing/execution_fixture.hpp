#pragma once

#include <charter/execution/engine.hpp>
#include <charter/schema/primitives.hpp>
#include <charter/storage/rocksdb/storage.hpp>
#include <charter/testing/common.hpp>
#include <charter/testing/execution_harness.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace charter::testing {

class execution_fixture final {
 public:
  explicit execution_fixture(const std::string_view db_prefix,
                             const bool strict_crypto = false,
                             const bool install_allow_all_verifier = true)
      : db_path_{make_db_path(db_prefix)},
        encoder_{},
        storage_{charter::storage::make_storage<
            charter::storage::rocksdb_storage_tag>(db_path_)},
        engine_{encoder_, storage_, 1, strict_crypto} {
    if (install_allow_all_verifier) {
      engine_.set_signature_verifier(allow_all_verifier());
    }
  }

  execution_fixture(const execution_fixture&) = delete;
  execution_fixture& operator=(const execution_fixture&) = delete;
  execution_fixture(execution_fixture&&) = delete;
  execution_fixture& operator=(execution_fixture&&) = delete;

  ~execution_fixture() { remove_path(db_path_); }

  const std::string& db_path() const { return db_path_; }

  scale_encoder_t& encoder() { return encoder_; }
  const scale_encoder_t& encoder() const { return encoder_; }

  charter::storage::storage<charter::storage::rocksdb_storage_tag>& storage() {
    return storage_;
  }
  const charter::storage::storage<charter::storage::rocksdb_storage_tag>&
  storage() const {
    return storage_;
  }

  charter::execution::engine& engine() { return engine_; }
  const charter::execution::engine& engine() const { return engine_; }

  charter::schema::hash32_t chain_id() {
    if (!chain_id_.has_value()) {
      chain_id_ = chain_id_from_engine(engine_);
    }
    return *chain_id_;
  }

  static charter::execution::signature_verifier_t allow_all_verifier() {
    return [](const charter::schema::bytes_view_t&,
              const charter::schema::signer_id_t&,
              const charter::schema::signature_t&) { return true; };
  }

 private:
  std::string db_path_;
  scale_encoder_t encoder_;
  charter::storage::storage<charter::storage::rocksdb_storage_tag> storage_;
  charter::execution::engine engine_;
  std::optional<charter::schema::hash32_t> chain_id_{std::nullopt};
};

}  // namespace charter::testing

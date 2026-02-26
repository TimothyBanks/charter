#include <charter/common/critical.hpp>
#include <charter/storage/rocksdb/storage.hpp>

namespace charter::storage {
template <>
storage<rocksdb_storage_tag> make_storage<rocksdb_storage_tag>(
    const std::string_view& path) {
  auto store = storage<rocksdb_storage_tag>();

  auto options = ROCKSDB_NAMESPACE::Options{};
  options.create_if_missing = true;
  options.IncreaseParallelism();
  options.OptimizeLevelStyleCompaction();

  ROCKSDB_NAMESPACE::DB* database{nullptr};
  auto status =
      ROCKSDB_NAMESPACE::DB::Open(options, std::string{path}, &database);
  if (!status.ok()) {
    spdlog::error("Failed to open RocksDB at {}: {}", path, status.ToString());
    charter::common::critical("Failed to open RocksDB");
  }
  spdlog::info("Successfully opened RocksDB at {}", path);
  store.database.reset(database);

  return store;
}
}  // namespace charter::storage

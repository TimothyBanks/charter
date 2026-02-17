#include <charter/storage/rocksdb/storage.hpp>

namespace charter::storage {
template <>
storage<rocksdb_storage_tag> make_storage<rocksdb_storage_tag>(
    const std::string_view& path) {
  auto store = storage<rocksdb_storage_tag>();

  ROCKSDB_NAMESPACE::Options options;
  options.create_if_missing = true;
  options.IncreaseParallelism();
  options.OptimizeLevelStyleCompaction();

  ROCKSDB_NAMESPACE::DB* database;
  ROCKSDB_NAMESPACE::Status status =
      ROCKSDB_NAMESPACE::DB::Open(options, std::string{path}, &database);
  if (!status.ok()) {
    spdlog::error("Failed to open RocksDB at {}: {}", path, status.ToString());
    throw std::runtime_error("Failed to open RocksDB");
  }
  spdlog::info("Successfully opened RocksDB at {}", path);
  store.database.reset(database);

  return store;
}
}  // namespace charter::storage
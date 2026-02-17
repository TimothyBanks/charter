#pragma once
#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/slice.h>
#include <spdlog/spdlog.h>
#include <charter/storage/storage.hpp>
#include <memory>

namespace charter::storage {

struct rocksdb_storage_tag {};

template <>
struct storage<rocksdb_storage_tag> final {
  std::unique_ptr<ROCKSDB_NAMESPACE::DB> database;

  template <typename Encoder, typename T>
  std::optional<T> get(Encoder& encoder, const charter::schema::bytes_t& key);

  template <typename Encoder, typename T>
  void put(Encoder& encoder, T value);
};

template <>
storage<rocksdb_storage_tag> make_storage<rocksdb_storage_tag>(
    const std::string_view& path);

template <typename Encoder, typename T>
std::optional<T> storage<rocksdb_storage_tag>::get(
    Encoder& encoder,
    const charter::schema::bytes_t& key) {
  assert(database);
  ROCKSDB_NAMESPACE::Slice key_slice(reinterpret_cast<const char*>(key.data()),
                                     key.size());
  std::string value;
  ROCKSDB_NAMESPACE::Status status =
      database->Get(ROCKSDB_NAMESPACE::ReadOptions(), key_slice, &value);
  if (!status.ok()) {
    if (status.IsNotFound()) {
      spdlog::info("Key not found in RocksDB");
      return std::nullopt;
    } else {
      spdlog::error("Failed to get value from RocksDB: {}", status.ToString());
      throw std::runtime_error("Failed to get value from RocksDB");
    }
  }
  return {encoder.template decode<T>(std::span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(value.data()), value.size()))};
}

template <typename Encoder, typename T>
void storage<rocksdb_storage_tag>::put(Encoder& encoder, T value) {
  assert(database);
  auto encoded_value = encoder.encode(value);
  ROCKSDB_NAMESPACE::Slice key_slice(
      reinterpret_cast<const char*>(encoded_value.data()),
      encoded_value.size());
  ROCKSDB_NAMESPACE::Status status = database->Put(
      ROCKSDB_NAMESPACE::WriteOptions(), key_slice, ROCKSDB_NAMESPACE::Slice());
  if (!status.ok()) {
    spdlog::error("Failed to put value into RocksDB: {}", status.ToString());
    throw std::runtime_error("Failed to put value into RocksDB");
  }
}

}  // namespace charter::storage
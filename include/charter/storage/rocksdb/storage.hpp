#pragma once
#include <rocksdb/db.h>
#include <rocksdb/iterator.h>
#include <rocksdb/options.h>
#include <rocksdb/slice.h>
#include <rocksdb/write_batch.h>
#include <spdlog/spdlog.h>
#include <charter/common/critical.hpp>
#include <charter/schema/encoding/scale/encoder.hpp>
#include <charter/storage/storage.hpp>
#include <iterator>
#include <memory>
#include <scale/scale.hpp>
#include <string_view>

namespace charter::storage {

namespace detail {

using encoder_t = charter::schema::encoding::encoder<
    charter::schema::encoding::scale_encoder_tag>;

inline constexpr auto kCommittedHeightKey =
    std::string_view{"SYS|APP|COMMITTED_HEIGHT"};
inline constexpr auto kSnapshotMetaPrefix = std::string_view{"SYS|SNAP|META|"};
inline constexpr auto kSnapshotChunkPrefix =
    std::string_view{"SYS|SNAP|CHUNK|"};

inline std::optional<std::pair<uint64_t, uint32_t>> parse_snapshot_meta_key(
    std::string_view key) {
  if (!key.starts_with(kSnapshotMetaPrefix)) {
    return std::nullopt;
  }
  auto encoder = encoder_t{};
  auto bytes = charter::schema::bytes_view_t{
      reinterpret_cast<const uint8_t*>(key.data() + kSnapshotMetaPrefix.size()),
      key.size() - kSnapshotMetaPrefix.size()};
  auto decoded = encoder.try_decode<std::tuple<uint64_t, uint32_t>>(bytes);
  if (!decoded.has_value()) {
    return std::nullopt;
  }
  return std::pair<uint64_t, uint32_t>{std::get<0>(decoded.value()),
                                       std::get<1>(decoded.value())};
}

inline std::string make_snapshot_meta_key(uint64_t height, uint32_t format) {
  auto encoder = encoder_t{};
  auto encoded = encoder.encode(std::tuple{height, format});
  auto key = std::string{kSnapshotMetaPrefix};
  key.append(reinterpret_cast<char*>(encoded.data()), encoded.size());
  return key;
}

inline std::string make_snapshot_chunk_key(uint64_t height,
                                           uint32_t format,
                                           uint32_t chunk) {
  auto encoder = encoder_t{};
  auto encoded = encoder.encode(std::tuple{height, format, chunk});
  auto key = std::string{kSnapshotChunkPrefix};
  key.append(reinterpret_cast<const char*>(encoded.data()), encoded.size());
  return key;
}

inline charter::schema::bytes_t to_bytes(
    const ROCKSDB_NAMESPACE::Slice& slice) {
  return {reinterpret_cast<const uint8_t*>(slice.data()),
          reinterpret_cast<const uint8_t*>(slice.data()) + slice.size()};
}

}  // namespace detail

struct rocksdb_storage_tag {};

template <>
struct storage<rocksdb_storage_tag> final {
  std::unique_ptr<ROCKSDB_NAMESPACE::DB> database;

  template <typename Encoder, typename T>
  std::optional<T> get(Encoder& encoder,
                       const charter::schema::bytes_view_t& key);

  template <typename Encoder, typename T>
  void put(Encoder& encoder,
           const charter::schema::bytes_view_t& key,
           const T& value);

  std::optional<committed_state> load_committed_state() const;
  void save_committed_state(const committed_state& state) const;
  std::vector<snapshot_descriptor> list_snapshots() const;
  void save_snapshot(const snapshot_descriptor& snapshot,
                     const charter::schema::bytes_t& chunk) const;
  std::optional<charter::schema::bytes_t>
  load_snapshot_chunk(uint64_t height, uint32_t format, uint32_t chunk) const;
  std::vector<key_value_entry_t> list_by_prefix(
      const charter::schema::bytes_view_t& prefix) const;
  void replace_by_prefix(const charter::schema::bytes_view_t& prefix,
                         const std::vector<key_value_entry_t>& entries) const;
};

template <>
storage<rocksdb_storage_tag> make_storage<rocksdb_storage_tag>(
    const std::string_view& path);

template <typename Encoder, typename T>
std::optional<T> storage<rocksdb_storage_tag>::get(
    Encoder& encoder,
    const charter::schema::bytes_view_t& key) {
  if (!database) {
    charter::common::critical("RocksDB database is not initialized");
  }
  auto key_slice = ROCKSDB_NAMESPACE::Slice{
      reinterpret_cast<const char*>(key.data()), key.size()};
  auto value = std::string{};
  auto status =
      database->Get(ROCKSDB_NAMESPACE::ReadOptions{}, key_slice, &value);
  if (!status.ok()) {
    if (status.IsNotFound()) {
      return std::nullopt;
    } else {
      spdlog::error("Failed to get value from RocksDB: {}", status.ToString());
      charter::common::critical("Failed to get value from RocksDB");
    }
  }
  return {encoder.template decode<T>(charter::schema::bytes_view_t{
      reinterpret_cast<const uint8_t*>(value.data()), value.size()})};
}

template <typename Encoder, typename T>
void storage<rocksdb_storage_tag>::put(Encoder& encoder,
                                       const charter::schema::bytes_view_t& key,
                                       const T& value) {
  if (!database) {
    charter::common::critical("RocksDB database is not initialized");
  }
  auto encoded_value = encoder.encode(value);
  auto key_slice = ROCKSDB_NAMESPACE::Slice{
      reinterpret_cast<const char*>(key.data()), key.size()};
  auto value_slice = ROCKSDB_NAMESPACE::Slice{
      reinterpret_cast<const char*>(encoded_value.data()),
      encoded_value.size()};
  auto status =
      database->Put(ROCKSDB_NAMESPACE::WriteOptions{}, key_slice, value_slice);
  if (!status.ok()) {
    spdlog::error("Failed to put value into RocksDB: {}", status.ToString());
    charter::common::critical("Failed to put value into RocksDB");
  }
}

inline std::optional<committed_state>
storage<rocksdb_storage_tag>::load_committed_state() const {
  if (!database) {
    charter::common::critical("RocksDB database is not initialized");
  }
  auto state = committed_state{};

  auto committed_raw = std::string{};
  auto committed_status =
      database->Get(ROCKSDB_NAMESPACE::ReadOptions{},
                    std::string{detail::kCommittedHeightKey}, &committed_raw);
  if (committed_status.IsNotFound()) {
    return std::nullopt;
  }
  if (!committed_status.ok()) {
    charter::common::critical("failed to load committed state");
  }

  auto encoder = detail::encoder_t{};
  auto decoded =
      encoder.try_decode<std::tuple<int64_t, charter::schema::hash32_t>>(
          charter::schema::bytes_view_t{
              reinterpret_cast<const uint8_t*>(committed_raw.data()),
              committed_raw.size()});
  if (!decoded.has_value()) {
    charter::common::critical("failed to decode committed state");
  }
  state.height = std::get<0>(decoded.value());
  state.app_hash = std::get<1>(decoded.value());

  return state;
}

inline void storage<rocksdb_storage_tag>::save_committed_state(
    const committed_state& state) const {
  if (!database) {
    charter::common::critical("RocksDB database is not initialized");
  }
  auto encoder = detail::encoder_t{};
  auto encoded = encoder.encode(std::tuple{state.height, state.app_hash});
  auto write_options = ROCKSDB_NAMESPACE::WriteOptions{};
  auto state_status =
      database->Put(write_options, std::string{detail::kCommittedHeightKey},
                    std::string{reinterpret_cast<const char*>(encoded.data()),
                                encoded.size()});
  if (!state_status.ok()) {
    charter::common::critical("failed to persist committed height");
  }
}

inline std::vector<snapshot_descriptor>
storage<rocksdb_storage_tag>::list_snapshots() const {
  if (!database) {
    charter::common::critical("RocksDB database is not initialized");
  }
  auto snapshots = std::vector<snapshot_descriptor>{};

  auto read_options = ROCKSDB_NAMESPACE::ReadOptions{};
  auto iterator = std::unique_ptr<ROCKSDB_NAMESPACE::Iterator>{
      database->NewIterator(read_options)};
  iterator->Seek(std::string{detail::kSnapshotMetaPrefix});

  while (iterator->Valid()) {
    auto key_view =
        std::string_view{iterator->key().data(), iterator->key().size()};
    if (!key_view.starts_with(detail::kSnapshotMetaPrefix)) {
      break;
    }

    auto parsed = detail::parse_snapshot_meta_key(key_view);
    if (!parsed) {
      iterator->Next();
      continue;
    }

    auto value = detail::to_bytes(iterator->value());
    auto encoder = detail::encoder_t{};
    auto decoded =
        encoder.try_decode<std::tuple<uint32_t, charter::schema::hash32_t,
                                      charter::schema::bytes_t>>(
            charter::schema::bytes_view_t{value.data(), value.size()});
    if (!decoded.has_value()) {
      spdlog::warn("Failed decoding snapshot metadata for key '{}'",
                   std::string{key_view});
      iterator->Next();
      continue;
    }

    auto snapshot = snapshot_descriptor{};
    snapshot.height = parsed->first;
    snapshot.format = parsed->second;
    snapshot.chunks = std::get<0>(decoded.value());
    snapshot.hash = std::get<1>(decoded.value());
    snapshot.metadata = std::get<2>(decoded.value());
    snapshots.push_back(std::move(snapshot));
    iterator->Next();
  }

  return snapshots;
}

inline void storage<rocksdb_storage_tag>::save_snapshot(
    const snapshot_descriptor& snapshot,
    const charter::schema::bytes_t& chunk) const {
  if (!database) {
    charter::common::critical("RocksDB database is not initialized");
  }
  auto meta_key =
      detail::make_snapshot_meta_key(snapshot.height, snapshot.format);
  auto chunk_key =
      detail::make_snapshot_chunk_key(snapshot.height, snapshot.format, 0);

  auto encoder = detail::encoder_t{};
  auto encoded_meta = encoder.encode(
      std::tuple{snapshot.chunks, snapshot.hash, snapshot.metadata});

  auto write_options = ROCKSDB_NAMESPACE::WriteOptions{};
  auto meta_status = database->Put(
      write_options, meta_key,
      std::string{reinterpret_cast<const char*>(encoded_meta.data()),
                  encoded_meta.size()});
  if (!meta_status.ok()) {
    charter::common::critical("failed to persist snapshot metadata");
  }

  auto chunk_status = database->Put(
      write_options, chunk_key,
      std::string{reinterpret_cast<const char*>(chunk.data()), chunk.size()});
  if (!chunk_status.ok()) {
    charter::common::critical("failed to persist snapshot chunk");
  }
}

inline std::optional<charter::schema::bytes_t>
storage<rocksdb_storage_tag>::load_snapshot_chunk(uint64_t height,
                                                  uint32_t format,
                                                  uint32_t chunk) const {
  if (!database) {
    charter::common::critical("RocksDB database is not initialized");
  }
  auto raw_value = std::string{};
  auto chunk_key = detail::make_snapshot_chunk_key(height, format, chunk);
  auto status =
      database->Get(ROCKSDB_NAMESPACE::ReadOptions{}, chunk_key, &raw_value);
  if (!status.ok()) {
    return std::nullopt;
  }
  return charter::schema::bytes_t(std::begin(raw_value), std::end(raw_value));
}

inline std::vector<key_value_entry_t>
storage<rocksdb_storage_tag>::list_by_prefix(
    const charter::schema::bytes_view_t& prefix) const {
  if (!database) {
    charter::common::critical("RocksDB database is not initialized");
  }

  auto entries = std::vector<key_value_entry_t>{};
  auto prefix_string =
      std::string{reinterpret_cast<const char*>(prefix.data()), prefix.size()};

  auto read_options = ROCKSDB_NAMESPACE::ReadOptions{};
  auto iterator = std::unique_ptr<ROCKSDB_NAMESPACE::Iterator>{
      database->NewIterator(read_options)};
  iterator->Seek(prefix_string);
  while (iterator->Valid()) {
    auto key_view =
        std::string_view{iterator->key().data(), iterator->key().size()};
    if (!key_view.starts_with(prefix_string)) {
      break;
    }
    entries.push_back(key_value_entry_t{detail::to_bytes(iterator->key()),
                                        detail::to_bytes(iterator->value())});
    iterator->Next();
  }
  return entries;
}

inline void storage<rocksdb_storage_tag>::replace_by_prefix(
    const charter::schema::bytes_view_t& prefix,
    const std::vector<key_value_entry_t>& entries) const {
  if (!database) {
    charter::common::critical("RocksDB database is not initialized");
  }

  auto prefix_string =
      std::string{reinterpret_cast<const char*>(prefix.data()), prefix.size()};
  auto read_options = ROCKSDB_NAMESPACE::ReadOptions{};
  auto iterator = std::unique_ptr<ROCKSDB_NAMESPACE::Iterator>{
      database->NewIterator(read_options)};
  auto batch = ROCKSDB_NAMESPACE::WriteBatch{};

  iterator->Seek(prefix_string);
  while (iterator->Valid()) {
    auto key_view =
        std::string_view{iterator->key().data(), iterator->key().size()};
    if (!key_view.starts_with(prefix_string)) {
      break;
    }
    auto delete_status = batch.Delete(iterator->key());
    if (!delete_status.ok()) {
      charter::common::critical(
          "failed deleting key during prefix replacement");
    }
    iterator->Next();
  }

  for (const auto& [key, value] : entries) {
    auto put_status = batch.Put(
        ROCKSDB_NAMESPACE::Slice{reinterpret_cast<const char*>(key.data()),
                                 key.size()},
        ROCKSDB_NAMESPACE::Slice{reinterpret_cast<const char*>(value.data()),
                                 value.size()});
    if (!put_status.ok()) {
      charter::common::critical("failed writing key during prefix replacement");
    }
  }

  auto write_status =
      database->Write(ROCKSDB_NAMESPACE::WriteOptions{}, &batch);
  if (!write_status.ok()) {
    charter::common::critical("failed to commit prefix replacement");
  }
}

}  // namespace charter::storage

#pragma once
#include <charter/schema/primitives.hpp>
#include <optional>
#include <vector>

namespace charter::storage {

using key_value_entry_t =
    std::pair<charter::schema::bytes_t, charter::schema::bytes_t>;

/// Last committed consensus checkpoint persisted by the storage backend.
struct committed_state final {
  int64_t height{};
  charter::schema::hash32_t state_root;
};

/// Snapshot metadata persisted by the storage backend.
struct snapshot_descriptor final {
  uint64_t height{};
  uint32_t format{1};
  uint32_t chunks{1};
  charter::schema::hash32_t hash;
  charter::schema::bytes_t metadata;
};

template <typename Library>
struct storage {
  /// Decode and return value at key, or std::nullopt when missing.
  template <typename T, typename Encoder>
  std::optional<T> get(Encoder& encoder,
                       const charter::schema::bytes_view_t& key);

  /// Encode and persist value at key.
  template <typename T, typename Encoder>
  void put(Encoder& encoder,
           const charter::schema::bytes_view_t& key,
           const T& value);

  /// Load the most recent committed checkpoint (height + state_root).
  template <typename Encoder>
  std::optional<committed_state> load_committed_state(Encoder& encoder) const;

  /// Persist the most recent committed checkpoint (height + state_root).
  template <typename Encoder>
  void save_committed_state(Encoder& encoder,
                            const committed_state& state) const;

  /// Enumerate available snapshots and their descriptors.
  template <typename Encoder>
  std::vector<snapshot_descriptor> list_snapshots(Encoder& encoder) const;

  /// Persist snapshot metadata and primary chunk payload.
  template <typename Encoder>
  void save_snapshot(Encoder& encoder,
                     const snapshot_descriptor& snapshot,
                     const charter::schema::bytes_t& chunk) const;

  /// Load a specific snapshot chunk payload by (height, format, chunk).
  template <typename Encoder>
  std::optional<charter::schema::bytes_t> load_snapshot_chunk(
      Encoder& encoder,
      uint64_t height,
      uint32_t format,
      uint32_t chunk) const;

  /// Return all key-value pairs that share the provided key prefix.
  std::vector<key_value_entry_t> list_by_prefix(
      const charter::schema::bytes_view_t& prefix) const;

  /// Atomically replace all entries under prefix with provided entries.
  void replace_by_prefix(const charter::schema::bytes_view_t& prefix,
                         const std::vector<key_value_entry_t>& entries) const;
};

/// Construct a concrete storage backend rooted at filesystem path.
template <typename Library>
storage<Library> make_storage(const std::string_view& path);

}  // namespace charter::storage

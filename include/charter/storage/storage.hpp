#pragma once
#include <charter/schema/primitives.hpp>
#include <optional>
#include <vector>

namespace charter::storage {

using key_value_entry_t =
    std::pair<charter::schema::bytes_t, charter::schema::bytes_t>;

struct committed_state final {
  int64_t height{};
  charter::schema::hash32_t app_hash;
};

struct snapshot_descriptor final {
  uint64_t height{};
  uint32_t format{1};
  uint32_t chunks{1};
  charter::schema::hash32_t hash;
  charter::schema::bytes_t metadata;
};

template <typename Library>
struct storage {
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

template <typename Library>
storage<Library> make_storage(const std::string_view& path);

}  // namespace charter::storage

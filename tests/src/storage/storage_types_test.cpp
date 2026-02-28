#include <charter/storage/storage.hpp>
#include <charter/storage/rocksdb/storage.hpp>
#include <charter/schema/encoding/scale/encoder.hpp>
#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>

namespace {

using storage_t = charter::storage::storage<charter::storage::rocksdb_storage_tag>;
using encoder_t =
    charter::schema::encoding::encoder<charter::schema::encoding::scale_encoder_tag>;

charter::schema::hash32_t make_hash(const uint8_t seed) {
  auto out = charter::schema::hash32_t{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(seed + static_cast<uint8_t>(i));
  }
  return out;
}

std::string make_db_path(const std::string& prefix) {
  auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  auto path = std::filesystem::temp_directory_path() /
              (prefix + "_" + std::to_string(static_cast<unsigned long long>(now)));
  return path.string();
}

}  // namespace

TEST(storage_types, defaults_are_stable) {
  auto committed = charter::storage::committed_state{};
  EXPECT_EQ(committed.height, 0);

  auto snapshot = charter::storage::snapshot_descriptor{};
  EXPECT_EQ(snapshot.height, 0u);
  EXPECT_EQ(snapshot.format, 1u);
  EXPECT_EQ(snapshot.chunks, 1u);

  auto entry = charter::storage::key_value_entry_t{};
  EXPECT_TRUE(entry.first.empty());
  EXPECT_TRUE(entry.second.empty());
}

TEST(storage_types, committed_state_round_trips) {
  auto db = make_db_path("charter_storage_committed");
  {
    auto storage = charter::storage::make_storage<charter::storage::rocksdb_storage_tag>(db);
    auto state = charter::storage::committed_state{
        .height = 42, .state_root = make_hash(10)};
    storage.save_committed_state(state);

    auto loaded = storage.load_committed_state();
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->height, state.height);
    EXPECT_EQ(loaded->state_root, state.state_root);
  }
  std::error_code ec;
  std::filesystem::remove_all(db, ec);
}

TEST(storage_types, snapshot_lifecycle_round_trips) {
  auto db = make_db_path("charter_storage_snapshot");
  {
    auto storage = charter::storage::make_storage<charter::storage::rocksdb_storage_tag>(db);
    auto snapshot = charter::storage::snapshot_descriptor{
        .height = 7,
        .format = 1,
        .chunks = 1,
        .hash = make_hash(22),
        .metadata = charter::schema::bytes_t{0xAA, 0xBB}};
    auto chunk = charter::schema::bytes_t{0x01, 0x02, 0x03, 0x04};
    storage.save_snapshot(snapshot, chunk);

    auto snapshots = storage.list_snapshots();
    ASSERT_EQ(snapshots.size(), 1u);
    EXPECT_EQ(snapshots[0].height, snapshot.height);
    EXPECT_EQ(snapshots[0].format, snapshot.format);
    EXPECT_EQ(snapshots[0].chunks, snapshot.chunks);
    EXPECT_EQ(snapshots[0].hash, snapshot.hash);
    EXPECT_EQ(snapshots[0].metadata, snapshot.metadata);

    auto loaded_chunk = storage.load_snapshot_chunk(snapshot.height, snapshot.format, 0);
    ASSERT_TRUE(loaded_chunk.has_value());
    EXPECT_EQ(*loaded_chunk, chunk);

    auto missing_chunk = storage.load_snapshot_chunk(snapshot.height, snapshot.format, 1);
    EXPECT_FALSE(missing_chunk.has_value());
  }
  std::error_code ec;
  std::filesystem::remove_all(db, ec);
}

TEST(storage_types, replace_by_prefix_rewrites_selected_keyspace_only) {
  auto db = make_db_path("charter_storage_prefix");
  {
    auto storage = charter::storage::make_storage<charter::storage::rocksdb_storage_tag>(db);
    auto encoder = encoder_t{};
    auto a_prefix = charter::schema::make_bytes(std::string_view{"A|"});
    auto b_prefix = charter::schema::make_bytes(std::string_view{"B|"});

    auto a1 = charter::schema::make_bytes(std::string_view{"A|one"});
    auto a2 = charter::schema::make_bytes(std::string_view{"A|two"});
    auto b1 = charter::schema::make_bytes(std::string_view{"B|one"});
    storage.put(encoder, charter::schema::bytes_view_t{a1.data(), a1.size()}, uint64_t{1});
    storage.put(encoder, charter::schema::bytes_view_t{a2.data(), a2.size()}, uint64_t{2});
    storage.put(encoder, charter::schema::bytes_view_t{b1.data(), b1.size()}, uint64_t{9});

    auto replacement = std::vector<charter::storage::key_value_entry_t>{};
    auto a3 = charter::schema::make_bytes(std::string_view{"A|three"});
    replacement.push_back({a3, encoder.encode(uint64_t{3})});
    storage.replace_by_prefix(
        charter::schema::bytes_view_t{a_prefix.data(), a_prefix.size()}, replacement);

    auto a_rows = storage.list_by_prefix(
        charter::schema::bytes_view_t{a_prefix.data(), a_prefix.size()});
    ASSERT_EQ(a_rows.size(), 1u);
    EXPECT_EQ(a_rows[0].first, a3);
    auto a_value = encoder.try_decode<uint64_t>(
        charter::schema::bytes_view_t{a_rows[0].second.data(), a_rows[0].second.size()});
    ASSERT_TRUE(a_value.has_value());
    EXPECT_EQ(a_value.value(), 3u);

    auto b_rows = storage.list_by_prefix(
        charter::schema::bytes_view_t{b_prefix.data(), b_prefix.size()});
    ASSERT_EQ(b_rows.size(), 1u);
    EXPECT_EQ(b_rows[0].first, b1);
    auto b_value = encoder.try_decode<uint64_t>(
        charter::schema::bytes_view_t{b_rows[0].second.data(), b_rows[0].second.size()});
    ASSERT_TRUE(b_value.has_value());
    EXPECT_EQ(b_value.value(), 9u);
  }
  std::error_code ec;
  std::filesystem::remove_all(db, ec);
}

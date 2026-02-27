#include <charter/storage/storage.hpp>
#include <gtest/gtest.h>

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

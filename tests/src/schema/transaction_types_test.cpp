#include <gtest/gtest.h>
#include <charter/schema/transaction.hpp>

TEST(transaction_types, defaults_are_stable) {
  auto tx = charter::schema::transaction_t{};
  EXPECT_EQ(tx.version, 1u);
  EXPECT_EQ(tx.nonce, 0u);
}

TEST(transaction_types, payload_variant_holds_valid_type) {
  auto tx = charter::schema::transaction_t{};
  tx.payload = charter::schema::create_workspace_t{};
  EXPECT_TRUE(
      std::holds_alternative<charter::schema::create_workspace_t>(tx.payload));
}

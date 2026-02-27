#include <charter/execution/engine.hpp>
#include <gtest/gtest.h>

TEST(engine_types, defaults_are_stable) {
  auto tx = charter::execution::tx_result{};
  EXPECT_EQ(tx.code, 0u);
  EXPECT_EQ(tx.gas_wanted, 0);
  EXPECT_EQ(tx.gas_used, 0);

  auto block = charter::execution::block_result{};
  EXPECT_TRUE(block.tx_results.empty());

  auto commit = charter::execution::commit_result{};
  EXPECT_EQ(commit.retain_height, 0);
  EXPECT_EQ(commit.committed_height, 0);

  auto info = charter::execution::app_info{};
  EXPECT_EQ(info.data, "charter-custody");
  EXPECT_EQ(info.version, "0.1.0-poc");
}

TEST(engine_types, verifier_callback_type_compiles) {
  auto verifier = charter::execution::signature_verifier_t{
      [](const charter::schema::bytes_view_t&,
         const charter::schema::signer_id_t&,
         const charter::schema::signature_t&) { return true; }};
  EXPECT_TRUE(static_cast<bool>(verifier));
}

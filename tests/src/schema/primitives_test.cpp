#include <charter/schema/primitives.hpp>
#include <gtest/gtest.h>

TEST(primitives, make_hash32_from_bytes_round_trips) {
  auto input = charter::schema::bytes_t(32, 0xAB);
  auto hash = charter::schema::make_hash32(input);
  EXPECT_EQ(hash.size(), 32u);
  EXPECT_EQ(hash[0], 0xAB);
  EXPECT_EQ(hash[31], 0xAB);
}

TEST(primitives, make_hash32_from_hex_string_decodes) {
  auto hash = charter::schema::make_hash32(
      std::string_view{"0x0102030405060708090a0b0c0d0e0f10"
                       "1112131415161718191a1b1c1d1e1f20"});
  EXPECT_EQ(hash[0], 0x01);
  EXPECT_EQ(hash[31], 0x20);
}

TEST(primitives, make_zero_hash_returns_zero_bytes) {
  auto zero = charter::schema::make_zero_hash();
  for (auto byte : zero) {
    EXPECT_EQ(byte, 0u);
  }
}

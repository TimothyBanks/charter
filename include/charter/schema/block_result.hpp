#pragma once

#include <charter/schema/primitives.hpp>
#include <charter/schema/transaction_result.hpp>
#include <cstdint>
#include <vector>

// Schema type: block result.
// Custody workflow: Finalize output: returns per-transaction results plus
// candidate post-block state root.
namespace charter::schema {

template <uint16_t Version>
struct block_result;

template <>
struct block_result<1> final {
  uint16_t version{1};
  std::vector<transaction_result_t> tx_results;
  hash32_t state_root;
};

using block_result_t = block_result<1>;

}  // namespace charter::schema

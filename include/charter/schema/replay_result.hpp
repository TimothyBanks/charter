#pragma once

#include <charter/schema/primitives.hpp>
#include <cstdint>
#include <string>

// Schema type: replay result.
// Custody workflow: Audit and determinism result: summarizes history replay
// verification against committed state.
namespace charter::schema {

template <uint16_t Version>
struct replay_result;

template <>
struct replay_result<1> final {
  uint16_t version{1};
  bool ok{};
  uint64_t tx_count{};
  uint64_t applied_count{};
  int64_t last_height{};
  hash32_t state_root;
  std::string error;
};

using replay_result_t = replay_result<1>;

}  // namespace charter::schema

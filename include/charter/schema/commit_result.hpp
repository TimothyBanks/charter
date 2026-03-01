#pragma once

#include <charter/schema/primitives.hpp>
#include <cstdint>

// Schema type: commit result.
// Custody workflow: Commit output: records finalized height/state_root
// persistence metadata for consensus handoff.
namespace charter::schema {

template <uint16_t Version>
struct commit_result;

template <>
struct commit_result<1> final {
  uint16_t version{1};
  int64_t retain_height{};
  int64_t committed_height{};
  hash32_t state_root;
};

using commit_result_t = commit_result<1>;

}  // namespace charter::schema

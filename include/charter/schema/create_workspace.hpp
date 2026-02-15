#pragma once
#include <charter/schema/primitives.hpp>
#include <optional>
#include <vector>

namespace charter::schema {

template <uint16_t Version> struct create_workspace;

template <> struct create_workspace<1> final {
  uint16_t version{1};
  hash32_t workspace_id;
  std::vector<public_key_t> admin_set; // must be sorted by key bytes
  uint32_t quorum_size{1};
  std::optional<hash32_t> metadata_ref; // hash of any off chain data
};

using create_workspace_t = create_workspace<1>;
using workspace_state_t = create_workspace<1>;

} // namespace charter::schema
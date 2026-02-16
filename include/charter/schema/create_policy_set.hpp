#pragma once
#include <charter/schema/policy_rule.hpp>
#include <charter/schema/primitives.hpp>
#include <charter/schema/role_id.hpp>
#include <optional>

namespace charter::schema {

template <uint16_t Version>
struct create_policy_set;

template <>
struct create_policy_set<1> final {
  uint16_t version{1};
  hash32_t policy_set_id;
  policy_scope_t scope;
  uint16_t policy_version{1};
  // must be sorted by role_id and the inner lexicographically
  std::vector<std::pair<role_id_t, std::vector<signer_id_t>>> roles;
  // must be sorted deterministically
  std::vector<policy_rule_t> rules;
};

using create_policy_set_t = create_policy_set<1>;
using policy_set_state_t = create_policy_set<1>;

}  // namespace charter::schema
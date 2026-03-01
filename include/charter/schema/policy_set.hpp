#pragma once
#include <charter/schema/policy_rule.hpp>
#include <charter/schema/primitives.hpp>
#include <charter/schema/role_id.hpp>

// Schema type: policy set.
// Custody workflow: Policy state container: stores executable governance rules
// used for intent authorization.
namespace charter::schema {

template <uint16_t Version>
struct policy_set;

template <>
struct policy_set<1> final {
  uint16_t version{1};
  hash32_t policy_set_id;
  policy_scope_t scope;
  uint16_t policy_version{1};
  // must be sorted by role_id and the inner lexicographically
  std::vector<std::pair<role_id_t, std::vector<signer_id_t>>> roles;
  // must be sorted deterministically
  std::vector<policy_rule_t> rules;
};

using policy_set_t = policy_set<1>;

}  // namespace charter::schema

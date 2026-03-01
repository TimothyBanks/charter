#pragma once
#include <charter/schema/primitives.hpp>

// Schema type: activate policy set.
// Custody workflow: Policy change control: promotes a policy set version to
// active enforcement for its scope.
namespace charter::schema {

template <uint16_t Version>
struct activate_policy_set;

template <>
struct activate_policy_set<1> final {
  uint16_t version{1};
  policy_scope_t scope;
  hash32_t policy_set_id;
  uint32_t policy_set_version;
};

using activate_policy_set_t = activate_policy_set<1>;

}  // namespace charter::schema

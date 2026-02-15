#pragma once
#include <charter/schema/approval_rule.hpp>
#include <charter/schema/claim_type.hpp>
#include <charter/schema/destiniation_rule.hpp>
#include <charter/schema/limit_rule.hpp>
#include <charter/schema/operation_type.hpp>
#include <charter/schema/primitives.hpp>
#include <charter/schema/time_lock_rule.hpp>
#include <optional>

namespace charter::schema {

template <uint16_t Version> struct policy_rule;

// TODO(tim): ask chatgpt about the vectors in this.
template <> struct policy_rule<1> final {
  uint16_t version{1};
  operation_type_t operation;
  std::vector<approval_rule_t> approvals; // must be sorted deterministically
  std::vector<limit_rule_t> limits;       // must be sorted deterministically
  std::optional<std::vector<time_lock_rule_t>>
      time_locks; // must be sorted deterministically
  std::vector<destination_rule_t>
      destination_rules;                    // must be sorted deterministically.
  std::vector<claim_type_t> reqired_claims; // must be sorted deterministically.
};

using policy_rule_t = policy_rule<1>;

} // namespace charter::schema
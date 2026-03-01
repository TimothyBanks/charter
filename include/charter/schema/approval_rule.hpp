#pragma once
#include <charter/schema/primitives.hpp>
#include <charter/schema/role_id.hpp>

// Schema type: approval rule.
// Custody workflow: Approval policy rule: defines thresholds and
// separation-of-duties constraints.
namespace charter::schema {

template <uint16_t Version>
struct approval_rule;

template <>
struct approval_rule<1> final {
  uint16_t version{1};
  role_id_t approver_role;
  uint32_t threshold;
  bool require_distinct_from_initiator{true};
  bool require_distinct_from_executor{true};
};

using approval_rule_t = approval_rule<1>;

}  // namespace charter::schema

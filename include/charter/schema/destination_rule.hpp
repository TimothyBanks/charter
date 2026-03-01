#pragma once
#include <charter/schema/primitives.hpp>

// Schema type: destination rule.
// Custody workflow: Destination policy rule: enforces whitelisting and
// destination safety constraints.
namespace charter::schema {

template <uint16_t Version>
struct destination_rule;

template <>
struct destination_rule<1> final {
  uint16_t version{1};
  bool require_whitelisted{true};
};

using destination_rule_t = destination_rule<1>;

}  // namespace charter::schema

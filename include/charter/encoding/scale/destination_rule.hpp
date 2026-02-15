#pragma once
#include <charter/schema/primitives.hpp>

namespace charter::schema {

template <uint16_t Version>
struct destination_rule;

template <>
struct destination_rule<1> final {
  const uint16_t version{1};
  bool require_whitelisted{true};
};

using destination_rule_t = destination_rule<1>;

}  // namespace charter::schema
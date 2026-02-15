#pragma once
#include <charter/schema/operation_type.hpp>
#include <charter/schema/primitives.hpp>

namespace charter::schema {

template <uint16_t Version> struct time_lock_rule;

template <> struct time_lock_rule<1> final {
  uint16_t version{1};
  operation_type_t operation;
  duration_milliseconds_t delay;
};

using time_lock_rule_t = time_lock_rule<1>;

} // namespace charter::schema
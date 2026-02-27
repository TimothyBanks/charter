#pragma once

#include <charter/schema/operation_type.hpp>
#include <charter/schema/primitives.hpp>
#include <charter/schema/velocity_window.hpp>
#include <optional>

namespace charter::schema {

template <uint16_t Version>
struct velocity_limit_rule;

template <>
struct velocity_limit_rule<1> final {
  uint16_t version{1};
  operation_type_t operation{operation_type_t::transfer};
  std::optional<asset_id_t> asset_id;
  velocity_window_t window{velocity_window_t::daily};
  amount_t maximum_amount{};
};

using velocity_limit_rule_t = velocity_limit_rule<1>;

}  // namespace charter::schema

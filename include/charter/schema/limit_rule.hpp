#pragma once
#include <charter/schema/primitives.hpp>

namespace charter::schema {

template <uint16_t Version>
struct limit_rule;

template <>
struct limit_rule<1> final {
  const uint16_t version{1};
  hash32_t asset_id;
  amount_t per_transaction_amount;
};

using limit_rule_t = limit_rule<1>;

}  // namespace charter::schema
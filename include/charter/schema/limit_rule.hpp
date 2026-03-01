#pragma once
#include <charter/schema/primitives.hpp>

// Schema type: limit rule.
// Custody workflow: Single-transaction limit rule: caps transfer value per
// intent.
namespace charter::schema {

template <uint16_t Version>
struct limit_rule;

template <>
struct limit_rule<1> final {
  uint16_t version{1};
  hash32_t asset_id;
  amount_t per_transaction_amount;
};

using limit_rule_t = limit_rule<1>;

}  // namespace charter::schema

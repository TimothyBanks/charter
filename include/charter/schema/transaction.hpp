#pragma once

#include <charter/schema/primitives.hpp>
#include "primitives.hpp"

namespace charter::schema {

enum transaction_type_t : uint16_t {
  create_workspace = 0,
  create_value = 1,
  upsert_destination = 2,
  create_policy_set = 3,
  activate_policy_set = 4,
  propose_intent = 5,
  approve_intent = 6,
  execute_intent = 7,
  cancel_intent = 8
};

template <uint16_t Version>
struct transaction;

template <>
struct transaction<1> final {
  const uint16_t version{1};
  hash32_t chain_id{};
  uint64_t nonce{};
  public_key_t signer{};
  transaction_type_t type{};
};

}  // namespace charter::schema
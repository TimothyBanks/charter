#pragma once
#include <charter/schema/intent_action.hpp>
#include <charter/schema/primitives.hpp>
#include <optional>
#include "primitives.hpp"

namespace charter::schema {

template <uint16_t Version>
struct propose_intent;

template <>
struct propose_intent<1> final {
  const uint16_t version{1};
  hash32_t workspace_id;
  hash32_t vault_id;
  hash32_t intent_id;
  intent_action_t action;
  std::optional<timestamp_milliseconds_t> expires_at;
};

using propose_intent_t = propose_intent<1>;

}  // namespace charter::schema
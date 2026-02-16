#pragma once
#include <charter/schema/primitives.hpp>

namespace charter::schema {

template <uint16_t Version>
struct cancel_intent;

template <>
struct cancel_intent<1> final {
  uint16_t version{1};
  hash32_t workspace_id;
  hash32_t vault_id;
  hash32_t intent_id;
};

using cancel_intent_t = cancel_intent<1>;

}  // namespace charter::schema
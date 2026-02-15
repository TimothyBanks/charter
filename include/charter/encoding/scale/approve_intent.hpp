#pragma once
#include <charter/schema/primitives.hpp>

namespace charter::schema {

template <uint16_t Version>
struct approve_intent;

template <>
struct approve_intent<1> final {
  constexpr static auto version = uint16_t{1};
  hash32_t workspace_id;
  hash32_t vault_id;
  hash32_t intent_id;
};

using approve_intent_t = approve_intent<1>;

}  // namespace charter::schema
#pragma once
#include <charter/schema/primitives.hpp>

// Schema type: execute intent.
// Custody workflow: Release execution: attempts to move an approved intent into
// executed state once all guards pass.
namespace charter::schema {

template <uint16_t Version>
struct execute_intent;

template <>
struct execute_intent<1> final {
  uint16_t version{1};
  hash32_t workspace_id;
  hash32_t vault_id;
  hash32_t intent_id;
};

using execute_intent_t = execute_intent<1>;

}  // namespace charter::schema

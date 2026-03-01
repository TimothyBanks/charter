#pragma once
#include <charter/schema/intent_action.hpp>
#include <charter/schema/primitives.hpp>
#include <charter/schema/settlement_authority_mode.hpp>
#include <optional>

// Schema type: propose intent.
// Custody workflow: Transfer initiation: creates a pending intent describing
// asset, destination, and amount under policy checks.
namespace charter::schema {

template <uint16_t Version>
struct propose_intent;

template <>
struct propose_intent<1> final {
  uint16_t version{1};
  hash32_t workspace_id;
  hash32_t vault_id;
  hash32_t intent_id;
  intent_action_t action;
  std::optional<timestamp_milliseconds_t> expires_at;
  // Selects who signs/submits the origin-chain settlement transaction once
  // Charter policy checks authorize this intent.
  settlement_authority_mode_t settlement_mode{
      settlement_authority_mode_t::custodian_signed};
};

using propose_intent_t = propose_intent<1>;

}  // namespace charter::schema

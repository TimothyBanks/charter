#pragma once

#include <charter/schema/primitives.hpp>
#include <optional>

// Schema type: settlement observation.
// Custody workflow: Evidence recorded from origin-chain settlement monitoring
// for a specific intent.
namespace charter::schema {

template <uint16_t Version>
struct settlement_observation;

template <>
struct settlement_observation<1> final {
  uint16_t version{1};
  // Origin-chain transaction hash for the submitted settlement.
  std::optional<hash32_t> transaction_hash;
  // Observed origin-chain block height when known.
  std::optional<uint64_t> block_height;
  // First time the settlement submission was observed.
  std::optional<timestamp_milliseconds_t> submitted_at;
  // Confirmation timestamp once settlement reaches finality policy.
  std::optional<timestamp_milliseconds_t> confirmed_at;
  // Optional operator/oracle supplied failure detail for failed settlement.
  std::optional<bytes_t> failure_reason;
};

using settlement_observation_t = settlement_observation<1>;

}  // namespace charter::schema

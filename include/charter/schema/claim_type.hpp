#pragma once
#include <charter/schema/primitives.hpp>
#include <cstdint>

// Schema type: claim type.
// Custody workflow: Claim classification type: canonical or custom claim
// identifiers for attestations.
namespace charter::schema {

enum class claim_type : uint16_t {
  kyb_verified = 0,
  sanctions_cleared = 1,
  travel_rule_ok = 2,
  risk_approved = 3,
};

// hash32 - user defined claim type.
using claim_type_t = std::variant<claim_type, hash32_t>;

}  // namespace charter::schema

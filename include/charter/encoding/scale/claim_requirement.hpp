#pragma once
#include <charter/schema/claim_type.hpp>
#include <charter/schema/primitives.hpp>
#include <optional>
#include <vector>
#include "primitives.hpp"

namespace charter::schema {

template <uint16_t Version>
struct claim_requirement;

template <>
struct claim_requirement<1> final {
  const uint16_t version{1};
  claim_type_t claim;
  std::optional<timestamp_milliseconds_t> minimum_valid_until;
  std::optional<std::vector<public_key_t>>
      trusted_issuers;  // must be sorted if present.
};

using claim_requirement_t = claim_requirement<1>;

}  // namespace charter::schema
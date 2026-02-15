#pragma once

#include <charter/schema/attestation_status.hpp>
#include <charter/schema/claim_type.hpp>
#include <charter/schema/primitives.hpp>
#include <optional>
#include "primitives.hpp"

namespace charter::schema {

template <uint16_t Version>
struct attestation_record;

template <>
struct attestation_record<1> final {
  const uint16_t version{1};
  // workspace_id or vault_id or identity_id (you choose)
  hash32_t subject;
  claim_type_t claim;
  public_key_t issuer;
  timestamp_milliseconds_t issued_at;
  timestamp_milliseconds_t expires_at;
  attestation_status_t status;
  // hash/pointer to off-chain case/doc evidence
  std::optional<hash32_t> reference_hash;
};

using attestation_record_t = attestation_record<1>;

}  // namespace charter::schema
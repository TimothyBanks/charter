#pragma once
#include <charter/schema/claim_type.hpp>
#include <charter/schema/primitives.hpp>
#include <optional>

namespace charter::schema {

template <uint16_t Version>
struct upsert_attestation;

template <>
struct upsert_attestation<1> final {
  const uint16_t version{1};
  hash32_t workspace_id;
  hash32_t subject;
  claim_type_t claim;
  // normally equals tx.signer (or Named id)
  public_key_t issuer;
  timestamp_milliseconds_t expires_at;
  std::optional<hash32_t> reference_hash;
};

using upsert_attestation_t = upsert_attestation<1>;

}  // namespace charter::schema
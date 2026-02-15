#pragma once
#include <charter/schema/claim_type.hpp>
#include <charter/schema/primitives.hpp>
#include <optional>

namespace charter::schema {

template <uint16_t Version>
struct revoke_attestation;

template <>
struct revoke_attestation<1> final {
  const uint16_t version{1};
  hash32_t workspace_id;
  hash32_t subject;
  claim_type_t claim;
  // normally equals tx.signer (or Named id)
  public_key_t issuer;
};

using revoke_attestation_t = revoke_attestation<1>;

}  // namespace charter::schema
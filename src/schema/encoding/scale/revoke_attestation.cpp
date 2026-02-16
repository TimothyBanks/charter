#include <charter/schema/encoding/scale/claim_type.hpp>
#include <charter/schema/encoding/scale/revoke_attestation.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(revoke_attestation<1> &&o, ::scale::Encoder &encoder) {
  encode(o.version, encoder);
  encode(o.workspace_id, encoder);
  encode(o.subject, encoder);
  encode(o.claim, encoder);
  encode(o.issuer, encoder);
}

void decode(revoke_attestation<1> &&o, ::scale::Decoder &decoder) {
  decode(o.version, decoder);
  decode(o.workspace_id, decoder);
  decode(o.subject, decoder);
  decode(o.claim, decoder);
  decode(o.issuer, decoder);
}

} // namespace charter::schema::encoding::scale
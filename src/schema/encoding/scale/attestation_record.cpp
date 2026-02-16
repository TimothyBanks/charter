#include <charter/schema/encoding/scale/attestation_record.hpp>
#include <charter/schema/encoding/scale/claim_type.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(attestation_record<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.workspace_id, encoder);
  encode(o.subject, encoder);
  encode(o.claim, encoder);
  encode(o.issuer, encoder);
  encode(o.issued_at, encoder);
  encode(o.expires_at, encoder);
  encode(o.status, encoder);
  encode(o.reference_hash, encoder);
}

void decode(attestation_record<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.workspace_id, decoder);
  decode(o.subject, decoder);
  decode(o.claim, decoder);
  decode(o.issuer, decoder);
  decode(o.issued_at, decoder);
  decode(o.expires_at, decoder);
  decode(o.status, decoder);
  decode(o.reference_hash, decoder);
}

}  // namespace charter::schema::encoding::scale
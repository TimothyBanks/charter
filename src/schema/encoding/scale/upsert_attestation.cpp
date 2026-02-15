#include <charter/schema/encoding/scale/upsert_attestation.hpp>

using namespace charter::schema;
using namespace charter::schema::encoding::scale;

void encode(upsert_attestation<1> &&o, ::scale::Encoder &encoder) {
  encode(o.version, encoder);
  encode(o.workspace_id, encoder);
  encode(o.subject, encoder);
  encode(o.claim, encoder);
  encode(o.issuer, encoder);
  encode(o.expires_at, encoder);
  encode(o.reference_hash, encoder);
}

void decode(upsert_attestation<1> &&o, ::scale::Decoder &decoder) {
  decode(o.version, decoder);
  decode(o.workspace_id, decoder);
  decode(o.subject, decoder);
  decode(o.claim, decoder);
  decode(o.issuer, decoder);
  decode(o.expires_at, decoder);
  decode(o.reference_hash, decoder);
}
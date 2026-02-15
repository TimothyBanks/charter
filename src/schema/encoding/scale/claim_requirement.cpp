#include <charter/schema/encoding/scale/claim_requirement.hpp>

using namespace charter::schema;
using namespace charter::schema::encoding::scale;

void encode(claim_requirement<1> &&o, ::scale::Encoder &encoder) {
  encode(o.version, encoder);
  encode(o.claim, encoder);
  encode(o.minimum_valid_until, encoder);
  encode(o.trusted_issuers, encoder);
}

void decode(claim_requirement<1> &&o, ::scale::Decoder &decoder) {
  decode(o.version, decoder);
  decode(o.claim, decoder);
  decode(o.minimum_valid_until, decoder);
  decode(o.trusted_issuers, decoder);
}
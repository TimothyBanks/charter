#include <charter/schema/encoding/scale/approval_state.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(approval_state<1> &&o, ::scale::Encoder &encoder) {
  encode(o.version, encoder);
  encode(o.intent_id, encoder);
  encode(o.signer, encoder);
  encode(o.signed_at, encoder);
}

void decode(approval_state<1> &&o, ::scale::Decoder &decoder) {
  decode(o.version, decoder);
  decode(o.intent_id, decoder);
  decode(o.signer, decoder);
  decode(o.signed_at, decoder);
}

} // namespace charter::schema::encoding::scale

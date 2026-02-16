#include <charter/schema/encoding/scale/propose_intent.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(propose_intent<1> &&o, ::scale::Encoder &encoder) {
  encode(o.version, encoder);
  encode(o.workspace_id, encoder);
  encode(o.vault_id, encoder);
  encode(o.intent_id, encoder);
  encode(o.action, encoder);
  encode(o.expires_at, encoder);
}

void decode(propose_intent<1> &&o, ::scale::Decoder &decoder) {
  decode(o.version, decoder);
  decode(o.workspace_id, decoder);
  decode(o.vault_id, decoder);
  decode(o.intent_id, decoder);
  decode(o.action, decoder);
  decode(o.expires_at, decoder);
}

}
#include <charter/schema/encoding/scale/create_vault.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(create_vault<1> &&o, ::scale::Encoder &encoder) {
  encode(o.version, encoder);
  encode(o.workspace_id, encoder);
  encode(o.vault_id, encoder);
  encode(o.model, encoder);
  encode(o.label, encoder);
}

void decode(create_vault<1> &&o, ::scale::Decoder &decoder) {
  decode(o.version, decoder);
  decode(o.workspace_id, decoder);
  decode(o.vault_id, decoder);
  decode(o.model, decoder);
  decode(o.label, decoder);
}

}
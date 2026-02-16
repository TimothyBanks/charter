#include <charter/schema/encoding/scale/chain.hpp>
#include <charter/schema/encoding/scale/upsert_destination.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(upsert_destination<1> &&o, ::scale::Encoder &encoder) {
  encode(o.version, encoder);
  encode(o.workspace_id, encoder);
  encode(o.destination_id, encoder);
  encode(o.type, encoder);
  encode(o.chain_type, encoder);
  encode(o.address_or_contract, encoder);
  encode(o.enabled, encoder);
  encode(o.label, encoder);
}

void decode(upsert_destination<1> &&o, ::scale::Decoder &decoder) {
  decode(o.version, decoder);
  decode(o.workspace_id, decoder);
  decode(o.destination_id, decoder);
  decode(o.type, decoder);
  decode(o.chain_type, decoder);
  decode(o.address_or_contract, decoder);
  decode(o.enabled, decoder);
  decode(o.label, decoder);
}

}
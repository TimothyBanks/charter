#include <charter/schema/encoding/scale/asset_kind.hpp>
#include <charter/schema/encoding/scale/asset_ref.hpp>
#include <charter/schema/encoding/scale/asset_state.hpp>
#include <charter/schema/encoding/scale/chain.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(asset_state<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.asset_id, encoder);
  encode(o.chain, encoder);
  encode(o.kind, encoder);
  encode(o.reference, encoder);
  encode(o.symbol, encoder);
  encode(o.name, encoder);
  encode(o.decimals, encoder);
  encode(o.enabled, encoder);
}

void decode(asset_state<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.asset_id, decoder);
  decode(o.chain, decoder);
  decode(o.kind, decoder);
  decode(o.reference, decoder);
  decode(o.symbol, decoder);
  decode(o.name, decoder);
  decode(o.decimals, decoder);
  decode(o.enabled, decoder);
}

}  // namespace charter::schema::encoding::scale

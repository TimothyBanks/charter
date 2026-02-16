#include <charter/schema/encoding/scale/asset_ref.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(asset_ref_native_symbol<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.symbol, encoder);
}

void decode(asset_ref_native_symbol<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.symbol, decoder);
}

void encode(asset_ref_contract_address<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.address, encoder);
}

void decode(asset_ref_contract_address<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.address, decoder);
}

void encode(asset_ref_composite<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.parts, encoder);
}

void decode(asset_ref_composite<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.parts, decoder);
}

}  // namespace charter::schema::encoding::scale

#include <charter/schema/encoding/scale/disable_asset.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(disable_asset<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.asset_id, encoder);
}

void decode(disable_asset<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.asset_id, decoder);
}

}  // namespace charter::schema::encoding::scale

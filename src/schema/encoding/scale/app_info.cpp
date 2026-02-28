#include <charter/schema/encoding/scale/app_info.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(app_info<1>&& o, ::scale::Encoder& encoder) {
  encode(o.schema_version, encoder);
  encode(o.data, encoder);
  encode(o.version, encoder);
  encode(o.app_version, encoder);
  encode(o.last_block_height, encoder);
  encode(o.last_block_state_root, encoder);
}

void decode(app_info<1>&& o, ::scale::Decoder& decoder) {
  decode(o.schema_version, decoder);
  decode(o.data, decoder);
  decode(o.version, decoder);
  decode(o.app_version, decoder);
  decode(o.last_block_height, decoder);
  decode(o.last_block_state_root, decoder);
}

}  // namespace charter::schema::encoding::scale

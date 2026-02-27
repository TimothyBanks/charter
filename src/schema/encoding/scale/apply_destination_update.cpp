#include <charter/schema/encoding/scale/apply_destination_update.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(apply_destination_update<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.workspace_id, encoder);
  encode(o.destination_id, encoder);
  encode(o.update_id, encoder);
}

void decode(apply_destination_update<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.workspace_id, decoder);
  decode(o.destination_id, decoder);
  decode(o.update_id, decoder);
}

}  // namespace charter::schema::encoding::scale

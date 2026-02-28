#include <charter/schema/encoding/scale/history_entry.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(history_entry<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.height, encoder);
  encode(o.index, encoder);
  encode(o.code, encoder);
  encode(o.tx, encoder);
}

void decode(history_entry<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.height, decoder);
  decode(o.index, decoder);
  decode(o.code, decoder);
  decode(o.tx, decoder);
}

}  // namespace charter::schema::encoding::scale

#include <charter/schema/encoding/scale/query_result.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(query_result<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.code, encoder);
  encode(o.log, encoder);
  encode(o.info, encoder);
  encode(o.key, encoder);
  encode(o.value, encoder);
  encode(o.height, encoder);
  encode(o.codespace, encoder);
}

void decode(query_result<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.code, decoder);
  decode(o.log, decoder);
  decode(o.info, decoder);
  decode(o.key, decoder);
  decode(o.value, decoder);
  decode(o.height, decoder);
  decode(o.codespace, decoder);
}

}  // namespace charter::schema::encoding::scale

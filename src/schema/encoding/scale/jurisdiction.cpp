#include <charter/schema/encoding/scale/jurisdiction.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(jurisdiction<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.jurisdiction_id, encoder);
}

void decode(jurisdiction<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.jurisdiction_id, decoder);
}

}  // namespace charter::schema::encoding::scale

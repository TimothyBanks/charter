#include <charter/schema/encoding/scale/destination_rule.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(destination_rule<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.require_whitelisted, encoder);
}

void decode(destination_rule<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.require_whitelisted, decoder);
}

}  // namespace charter::schema::encoding::scale
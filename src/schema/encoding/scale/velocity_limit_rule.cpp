#include <charter/schema/encoding/scale/velocity_limit_rule.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(velocity_limit_rule<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.operation, encoder);
  encode(o.asset_id, encoder);
  encode(o.window, encoder);
  encode(o.maximum_amount, encoder);
}

void decode(velocity_limit_rule<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.operation, decoder);
  decode(o.asset_id, decoder);
  decode(o.window, decoder);
  decode(o.maximum_amount, decoder);
}

}  // namespace charter::schema::encoding::scale

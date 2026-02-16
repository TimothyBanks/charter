#include <charter/schema/encoding/scale/limit_rule.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(limit_rule<1> &&o, ::scale::Encoder &encoder) {
  encode(o.version, encoder);
  encode(o.asset_id, encoder);
  encode(o.per_transaction_amount, encoder);
}

void decode(limit_rule<1> &&o, ::scale::Decoder &decoder) {
  decode(o.version, decoder);
  decode(o.asset_id, decoder);
  decode(o.per_transaction_amount, decoder);
}

} // namespace charter::schema::encoding::scale
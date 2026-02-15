#include <charter/schema/encoding/scale/time_lock_rule.hpp>

using namespace charter::schema;
using namespace charter::schema::encoding::scale;

void encode(time_lock_rule<1> &&o, ::scale::Encoder &encoder) {
  encode(o.version, encoder);
  encode(o.operation, encoder);
  encode(o.delay, encoder);
}

void decode(time_lock_rule<1> &&o, ::scale::Decoder &decoder) {
  decode(o.version, decoder);
  decode(o.operation, decoder);
  decode(o.delay, decoder);
}
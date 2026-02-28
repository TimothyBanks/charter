#include <charter/schema/encoding/scale/transaction_event_attribute.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(transaction_event_attribute<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.key, encoder);
  encode(o.value, encoder);
  encode(o.index, encoder);
}

void decode(transaction_event_attribute<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.key, decoder);
  decode(o.value, decoder);
  decode(o.index, decoder);
}

}  // namespace charter::schema::encoding::scale

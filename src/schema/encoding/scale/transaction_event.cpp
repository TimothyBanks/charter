#include <charter/schema/encoding/scale/transaction_event.hpp>
#include <charter/schema/encoding/scale/transaction_event_attribute.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(transaction_event<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.type, encoder);
  encode(o.attributes, encoder);
}

void decode(transaction_event<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.type, decoder);
  decode(o.attributes, decoder);
}

}  // namespace charter::schema::encoding::scale

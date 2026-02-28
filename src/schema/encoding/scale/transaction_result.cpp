#include <charter/schema/encoding/scale/transaction_event.hpp>
#include <charter/schema/encoding/scale/transaction_result.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(transaction_result<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.code, encoder);
  encode(o.data, encoder);
  encode(o.log, encoder);
  encode(o.info, encoder);
  encode(o.gas_wanted, encoder);
  encode(o.gas_used, encoder);
  encode(o.codespace, encoder);
  encode(o.events, encoder);
}

void decode(transaction_result<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.code, decoder);
  decode(o.data, decoder);
  decode(o.log, decoder);
  decode(o.info, decoder);
  decode(o.gas_wanted, decoder);
  decode(o.gas_used, decoder);
  decode(o.codespace, decoder);
  decode(o.events, decoder);
}

}  // namespace charter::schema::encoding::scale

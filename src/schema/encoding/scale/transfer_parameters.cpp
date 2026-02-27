#include <charter/schema/encoding/scale/transfer_parameters.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(transfer_parameters<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.asset_id, encoder);
  encode(o.destination_id, encoder);
  encode(o.amount, encoder);
}

void decode(transfer_parameters<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.asset_id, decoder);
  decode(o.destination_id, decoder);
  decode(o.amount, decoder);
}

}  // namespace charter::schema::encoding::scale

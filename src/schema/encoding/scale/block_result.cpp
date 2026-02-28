#include <charter/schema/encoding/scale/block_result.hpp>
#include <charter/schema/encoding/scale/transaction_result.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(block_result<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.tx_results, encoder);
  encode(o.state_root, encoder);
}

void decode(block_result<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.tx_results, decoder);
  decode(o.state_root, decoder);
}

}  // namespace charter::schema::encoding::scale

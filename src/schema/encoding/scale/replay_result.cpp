#include <charter/schema/encoding/scale/replay_result.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(replay_result<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.ok, encoder);
  encode(o.tx_count, encoder);
  encode(o.applied_count, encoder);
  encode(o.last_height, encoder);
  encode(o.state_root, encoder);
  encode(o.error, encoder);
}

void decode(replay_result<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.ok, decoder);
  decode(o.tx_count, decoder);
  decode(o.applied_count, decoder);
  decode(o.last_height, decoder);
  decode(o.state_root, decoder);
  decode(o.error, decoder);
}

}  // namespace charter::schema::encoding::scale

#include <charter/schema/encoding/scale/set_degraded_mode.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(set_degraded_mode<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.mode, encoder);
  encode(o.effective_at, encoder);
  encode(o.reason, encoder);
}

void decode(set_degraded_mode<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.mode, decoder);
  decode(o.effective_at, decoder);
  decode(o.reason, decoder);
}

}  // namespace charter::schema::encoding::scale

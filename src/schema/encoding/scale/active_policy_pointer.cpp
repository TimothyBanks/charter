#include <charter/schema/encoding/scale/active_policy_pointer.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(active_policy_pointer<1> &&o, ::scale::Encoder &encoder) {
  encode(o.version, encoder);
  encode(o.policy_set_id, encoder);
  encode(o.policy_set_version, encoder);
}

void decode(active_policy_pointer<1> &&o, ::scale::Decoder &decoder) {
  decode(o.version, decoder);
  decode(o.policy_set_id, decoder);
  decode(o.policy_set_version, decoder);
}

} // namespace charter::schema::encoding::scale

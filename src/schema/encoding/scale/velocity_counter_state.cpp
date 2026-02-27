#include <charter/schema/encoding/scale/velocity_counter_state.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(velocity_counter_state<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.workspace_id, encoder);
  encode(o.vault_id, encoder);
  encode(o.asset_id, encoder);
  encode(o.window, encoder);
  encode(o.window_start, encoder);
  encode(o.used_amount, encoder);
  encode(o.tx_count, encoder);
}

void decode(velocity_counter_state<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.workspace_id, decoder);
  decode(o.vault_id, decoder);
  decode(o.asset_id, decoder);
  decode(o.window, decoder);
  decode(o.window_start, decoder);
  decode(o.used_amount, decoder);
  decode(o.tx_count, decoder);
}

}  // namespace charter::schema::encoding::scale

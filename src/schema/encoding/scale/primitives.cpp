#include <charter/schema/encoding/scale/primitives.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(workspace_scope_t&& o, ::scale::Encoder& encoder) {
  encode(o.workspace_id, encoder);
}

void decode(workspace_scope_t&& o, ::scale::Decoder& decoder) {
  decode(o.workspace_id, decoder);
}

void encode(vault_t&& o, ::scale::Encoder& encoder) {
  encode(o.workspace_id, encoder);
  encode(o.vault_id, encoder);
}

void decode(vault_t&& o, ::scale::Decoder& decoder) {
  decode(o.workspace_id, decoder);
  decode(o.vault_id, decoder);
}

}  // namespace charter::schema::encoding::scale

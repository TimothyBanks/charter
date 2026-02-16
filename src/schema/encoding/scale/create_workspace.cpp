#include <charter/schema/encoding/scale/create_workspace.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(create_workspace<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.workspace_id, encoder);
  encode(o.admin_set, encoder);
  encode(o.quorum_size, encoder);
  encode(o.metadata_ref, encoder);
}

void decode(create_workspace<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.workspace_id, decoder);
  decode(o.admin_set, decoder);
  decode(o.quorum_size, decoder);
  decode(o.metadata_ref, decoder);
}

}  // namespace charter::schema::encoding::scale
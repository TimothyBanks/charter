#include <charter/schema/encoding/scale/upsert_role_assignment.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(upsert_role_assignment<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.scope, encoder);
  encode(o.subject, encoder);
  encode(o.role, encoder);
  encode(o.enabled, encoder);
  encode(o.not_before, encoder);
  encode(o.expires_at, encoder);
  encode(o.note, encoder);
}

void decode(upsert_role_assignment<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.scope, decoder);
  decode(o.subject, decoder);
  decode(o.role, decoder);
  decode(o.enabled, decoder);
  decode(o.not_before, decoder);
  decode(o.expires_at, decoder);
  decode(o.note, decoder);
}

}  // namespace charter::schema::encoding::scale

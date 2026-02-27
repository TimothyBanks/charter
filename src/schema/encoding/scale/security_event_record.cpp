#include <charter/schema/encoding/scale/security_event_record.hpp>
#include <charter/schema/encoding/scale/security_event_severity.hpp>
#include <charter/schema/encoding/scale/security_event_type.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(security_event_record<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.event_id, encoder);
  encode(o.height, encoder);
  encode(o.tx_index, encoder);
  encode(o.type, encoder);
  encode(o.severity, encoder);
  encode(o.code, encoder);
  encode(o.message, encoder);
  encode(o.signer, encoder);
  encode(o.workspace_id, encoder);
  encode(o.vault_id, encoder);
  encode(o.recorded_at, encoder);
}

void decode(security_event_record<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.event_id, decoder);
  decode(o.height, decoder);
  decode(o.tx_index, decoder);
  decode(o.type, decoder);
  decode(o.severity, decoder);
  decode(o.code, decoder);
  decode(o.message, decoder);
  decode(o.signer, decoder);
  decode(o.workspace_id, decoder);
  decode(o.vault_id, decoder);
  decode(o.recorded_at, decoder);
}

}  // namespace charter::schema::encoding::scale

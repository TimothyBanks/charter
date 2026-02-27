#include <charter/schema/encoding/scale/upsert_signer_quarantine.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(upsert_signer_quarantine<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.signer, encoder);
  encode(o.quarantined, encoder);
  encode(o.until, encoder);
  encode(o.reason, encoder);
}

void decode(upsert_signer_quarantine<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.signer, decoder);
  decode(o.quarantined, decoder);
  decode(o.until, decoder);
  decode(o.reason, decoder);
}

}  // namespace charter::schema::encoding::scale

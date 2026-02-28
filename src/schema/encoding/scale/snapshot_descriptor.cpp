#include <charter/schema/encoding/scale/snapshot_descriptor.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(snapshot_descriptor<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.height, encoder);
  encode(o.format, encoder);
  encode(o.chunks, encoder);
  encode(o.hash, encoder);
  encode(o.metadata, encoder);
}

void decode(snapshot_descriptor<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.height, decoder);
  decode(o.format, decoder);
  decode(o.chunks, decoder);
  decode(o.hash, decoder);
  decode(o.metadata, decoder);
}

}  // namespace charter::schema::encoding::scale

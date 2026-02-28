#include <charter/schema/encoding/scale/commit_result.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(commit_result<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.retain_height, encoder);
  encode(o.committed_height, encoder);
  encode(o.state_root, encoder);
}

void decode(commit_result<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.retain_height, decoder);
  decode(o.committed_height, decoder);
  decode(o.state_root, decoder);
}

}  // namespace charter::schema::encoding::scale

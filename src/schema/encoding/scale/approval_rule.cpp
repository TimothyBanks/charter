#include <charter/schema/encoding/scale/approval_rule.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(approval_rule<1> &&o, ::scale::Encoder &encoder) {
  encode(o.version, encoder);
  encode(o.approver_role, encoder);
  encode(o.threshold, encoder);
  encode(o.require_distinct_from_initiator, encoder);
  encode(o.require_distinct_from_executor, encoder);
}

void decode(approval_rule<1> &&o, ::scale::Decoder &decoder) {
  decode(o.version, decoder);
  decode(o.approver_role, decoder);
  decode(o.threshold, decoder);
  decode(o.require_distinct_from_initiator, decoder);
  decode(o.require_distinct_from_executor, decoder);
}

}

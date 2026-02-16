#include <charter/schema/encoding/scale/claim_type.hpp>
#include <charter/schema/encoding/scale/policy_rule.hpp>
#include <charter/schema/encoding/scale/policy_set.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(policy_set<1> &&o, ::scale::Encoder &encoder) {
  encode(o.version, encoder);
  encode(o.policy_set_id, encoder);
  encode(o.scope, encoder);
  encode(o.policy_version, encoder);
  encode(o.roles, encoder);
  encode(o.rules, encoder);
}

void decode(policy_set<1> &&o, ::scale::Decoder &decoder) {
  decode(o.version, decoder);
  decode(o.policy_set_id, decoder);
  decode(o.scope, decoder);
  decode(o.policy_version, decoder);
  decode(o.roles, decoder);
  decode(o.rules, decoder);
}

} // namespace charter::schema::encoding::scale
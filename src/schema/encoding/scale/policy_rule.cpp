#include <charter/schema/encoding/scale/approval_rule.hpp>
#include <charter/schema/encoding/scale/claim_type.hpp>
#include <charter/schema/encoding/scale/destination_rule.hpp>
#include <charter/schema/encoding/scale/limit_rule.hpp>
#include <charter/schema/encoding/scale/policy_rule.hpp>
#include <charter/schema/encoding/scale/time_lock_rule.hpp>
#include <charter/schema/encoding/scale/velocity_limit_rule.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(policy_rule<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.operation, encoder);
  encode(o.approvals, encoder);
  encode(o.limits, encoder);
  encode(o.time_locks, encoder);
  encode(o.destination_rules, encoder);
  encode(o.required_claims, encoder);
  encode(o.velocity_limits, encoder);
}

void decode(policy_rule<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.operation, decoder);
  decode(o.approvals, decoder);
  decode(o.limits, decoder);
  decode(o.time_locks, decoder);
  decode(o.destination_rules, decoder);
  decode(o.required_claims, decoder);
  decode(o.velocity_limits, decoder);
}

}  // namespace charter::schema::encoding::scale

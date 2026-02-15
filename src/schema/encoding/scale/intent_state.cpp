#include <charter/schema/encoding/scale/claim_requirement.hpp>
#include <charter/schema/encoding/scale/intent_state.hpp>

using namespace charter::schema;
using namespace charter::schema::encoding::scale;

void encode(intent_state<1> &&o, ::scale::Encoder &encoder) {
  encode(o.version, encoder);
  encode(o.workspace_id, encoder);
  encode(o.vault_id, encoder);
  encode(o.intent_id, encoder);
  encode(o.created_by, encoder);
  encode(o.create_at, encoder);
  encode(o.not_before, encoder);
  encode(o.expires_at, encoder);
  encode(o.action, encoder);
  encode(o.status, encoder);
  encode(o.policy_set_id, encoder);
  encode(o.policy_version, encoder);
  encode(o.required_threshold, encoder);
  encode(o.approvals_count, encoder);
  encode(o.claim_requirements, encoder);
}

void decode(intent_state<1> &&o, ::scale::Decoder &decoder) {
  decode(o.version, decoder);
  decode(o.workspace_id, decoder);
  decode(o.vault_id, decoder);
  decode(o.intent_id, decoder);
  decode(o.created_by, decoder);
  decode(o.create_at, decoder);
  decode(o.not_before, decoder);
  decode(o.expires_at, decoder);
  decode(o.action, decoder);
  decode(o.status, decoder);
  decode(o.policy_set_id, decoder);
  decode(o.policy_version, decoder);
  decode(o.required_threshold, decoder);
  decode(o.approvals_count, decoder);
  decode(o.claim_requirements, decoder);
}
#include <charter/schema/encoding/scale/activate_policy_set.hpp>
#include <charter/schema/encoding/scale/apply_destination_update.hpp>
#include <charter/schema/encoding/scale/approve_destination_update.hpp>
#include <charter/schema/encoding/scale/approve_intent.hpp>
#include <charter/schema/encoding/scale/cancel_intent.hpp>
#include <charter/schema/encoding/scale/chain.hpp>
#include <charter/schema/encoding/scale/claim_type.hpp>
#include <charter/schema/encoding/scale/create_policy_set.hpp>
#include <charter/schema/encoding/scale/create_vault.hpp>
#include <charter/schema/encoding/scale/create_workspace.hpp>
#include <charter/schema/encoding/scale/execute_intent.hpp>
#include <charter/schema/encoding/scale/propose_destination_update.hpp>
#include <charter/schema/encoding/scale/propose_intent.hpp>
#include <charter/schema/encoding/scale/revoke_attestation.hpp>
#include <charter/schema/encoding/scale/set_degraded_mode.hpp>
#include <charter/schema/encoding/scale/transaction.hpp>
#include <charter/schema/encoding/scale/upsert_attestation.hpp>
#include <charter/schema/encoding/scale/upsert_destination.hpp>
#include <charter/schema/encoding/scale/upsert_role_assignment.hpp>
#include <charter/schema/encoding/scale/upsert_signer_quarantine.hpp>

using namespace charter::schema;

namespace charter::schema::encoding::scale {

void encode(transaction<1>&& o, ::scale::Encoder& encoder) {
  encode(o.version, encoder);
  encode(o.chain_id, encoder);
  encode(o.nonce, encoder);
  encode(o.signer, encoder);
  encode(o.payload, encoder);
  //  TODO(tim): This should not be encoded for signing.
  encode(o.signature, encoder);
}

void decode(transaction<1>&& o, ::scale::Decoder& decoder) {
  decode(o.version, decoder);
  decode(o.chain_id, decoder);
  decode(o.nonce, decoder);
  decode(o.signer, decoder);
  decode(o.payload, decoder);
  decode(o.signature, decoder);
}

}  // namespace charter::schema::encoding::scale

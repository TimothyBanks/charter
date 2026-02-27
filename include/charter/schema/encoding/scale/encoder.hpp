#pragma once
#include <charter/common/critical.hpp>
#include <charter/schema/encoding/encoder.hpp>
#include <charter/schema/encoding/scale/activate_policy_set.hpp>
#include <charter/schema/encoding/scale/active_policy_pointer.hpp>
#include <charter/schema/encoding/scale/apply_destination_update.hpp>
#include <charter/schema/encoding/scale/approval_rule.hpp>
#include <charter/schema/encoding/scale/approval_state.hpp>
#include <charter/schema/encoding/scale/approve_destination_update.hpp>
#include <charter/schema/encoding/scale/approve_intent.hpp>
#include <charter/schema/encoding/scale/attestation_record.hpp>
#include <charter/schema/encoding/scale/attestation_status.hpp>
#include <charter/schema/encoding/scale/cancel_intent.hpp>
#include <charter/schema/encoding/scale/chain.hpp>
#include <charter/schema/encoding/scale/claim_requirement.hpp>
#include <charter/schema/encoding/scale/claim_type.hpp>
#include <charter/schema/encoding/scale/create_policy_set.hpp>
#include <charter/schema/encoding/scale/create_vault.hpp>
#include <charter/schema/encoding/scale/create_workspace.hpp>
#include <charter/schema/encoding/scale/degraded_mode.hpp>
#include <charter/schema/encoding/scale/destination_rule.hpp>
#include <charter/schema/encoding/scale/destination_type.hpp>
#include <charter/schema/encoding/scale/destination_update_state.hpp>
#include <charter/schema/encoding/scale/destination_update_status.hpp>
#include <charter/schema/encoding/scale/execute_intent.hpp>
#include <charter/schema/encoding/scale/intent_state.hpp>
#include <charter/schema/encoding/scale/intent_status.hpp>
#include <charter/schema/encoding/scale/limit_rule.hpp>
#include <charter/schema/encoding/scale/operation_type.hpp>
#include <charter/schema/encoding/scale/policy_rule.hpp>
#include <charter/schema/encoding/scale/policy_set.hpp>
#include <charter/schema/encoding/scale/primitives.hpp>
#include <charter/schema/encoding/scale/propose_destination_update.hpp>
#include <charter/schema/encoding/scale/propose_intent.hpp>
#include <charter/schema/encoding/scale/revoke_attestation.hpp>
#include <charter/schema/encoding/scale/role_id.hpp>
#include <charter/schema/encoding/scale/security_event_record.hpp>
#include <charter/schema/encoding/scale/security_event_severity.hpp>
#include <charter/schema/encoding/scale/security_event_type.hpp>
#include <charter/schema/encoding/scale/set_degraded_mode.hpp>
#include <charter/schema/encoding/scale/time_lock_rule.hpp>
#include <charter/schema/encoding/scale/transaction.hpp>
#include <charter/schema/encoding/scale/transfer_parameters.hpp>
#include <charter/schema/encoding/scale/upsert_attestation.hpp>
#include <charter/schema/encoding/scale/upsert_destination.hpp>
#include <charter/schema/encoding/scale/upsert_role_assignment.hpp>
#include <charter/schema/encoding/scale/upsert_signer_quarantine.hpp>
#include <charter/schema/encoding/scale/vault_model.hpp>
#include <charter/schema/encoding/scale/velocity_counter_state.hpp>
#include <charter/schema/encoding/scale/velocity_limit_rule.hpp>
#include <charter/schema/encoding/scale/velocity_window.hpp>
#include <iterator>
#include <scale/scale.hpp>

namespace charter::schema::encoding {

struct scale_encoder_tag {};

template <>
struct encoder<scale_encoder_tag> final {
  template <typename T>
  charter::schema::bytes_t encode(const T& obj);

  template <typename T>
  void encode(const T& obj, charter::schema::bytes_t& out);

  template <typename T>
  T decode(const charter::schema::bytes_view_t& bytes);

  template <typename T>
  std::optional<T> try_decode(const charter::schema::bytes_view_t& bytes);
};

template <typename T>
charter::schema::bytes_t encoder<scale_encoder_tag>::encode(const T& obj) {
  auto encoded = ::scale::impl::memory::encode(obj);
  if (!encoded) {
    charter::common::critical("failed to encode SCALE object");
  }
  return encoded.value();
}

template <typename T>
void encoder<scale_encoder_tag>::encode(const T& obj,
                                        charter::schema::bytes_t& out) {
  auto encoded = encode(obj);
  out.insert(std::end(out), std::begin(encoded), std::end(encoded));
}

template <typename T>
T encoder<scale_encoder_tag>::decode(
    const charter::schema::bytes_view_t& bytes) {
  auto decoded = ::scale::impl::memory::decode<T>(bytes);
  if (!decoded) {
    charter::common::critical("failed to decode SCALE bytes");
  }
  return decoded.value();
}

template <typename T>
std::optional<T> encoder<scale_encoder_tag>::try_decode(
    const charter::schema::bytes_view_t& bytes) {
  auto decoded = ::scale::impl::memory::decode<T>(bytes);
  if (!decoded) {
    return std::nullopt;
  }
  return decoded.value();
}

}  // namespace charter::schema::encoding

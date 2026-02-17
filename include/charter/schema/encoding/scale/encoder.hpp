#pragma once
#include <charter/schema/encoding/encoder.hpp>
#include <charter/schema/encoding/scale/activate_policy_set.hpp>
#include <charter/schema/encoding/scale/active_policy_pointer.hpp>
#include <charter/schema/encoding/scale/approval_rule.hpp>
#include <charter/schema/encoding/scale/approval_state.hpp>
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
#include <charter/schema/encoding/scale/destination_rule.hpp>
#include <charter/schema/encoding/scale/destination_type.hpp>
#include <charter/schema/encoding/scale/execute_intent.hpp>
#include <charter/schema/encoding/scale/intent_action.hpp>
#include <charter/schema/encoding/scale/intent_state.hpp>
#include <charter/schema/encoding/scale/intent_status.hpp>
#include <charter/schema/encoding/scale/limit_rule.hpp>
#include <charter/schema/encoding/scale/operation_type.hpp>
#include <charter/schema/encoding/scale/policy_rule.hpp>
#include <charter/schema/encoding/scale/policy_set.hpp>
#include <charter/schema/encoding/scale/propose_intent.hpp>
#include <charter/schema/encoding/scale/revoke_attestation.hpp>
#include <charter/schema/encoding/scale/role_id.hpp>
#include <charter/schema/encoding/scale/time_lock_rule.hpp>
#include <charter/schema/encoding/scale/transaction.hpp>
#include <charter/schema/encoding/scale/transfer_parameters.hpp>
#include <charter/schema/encoding/scale/upsert_attestation.hpp>
#include <charter/schema/encoding/scale/upsert_destination.hpp>
#include <charter/schema/encoding/scale/vault_model.hpp>
#include <scale/scale.hpp>

namespace charter::charter::schema::encoding {

struct scale_encoder_tag {};

template <>
struct encoder<scale_encoder_tag> final {
  template <typename T>
  charter::schema::bytes_t encode(const T& obj);

  template <typename T>
  void encode(const T& obj, charter::schema::bytes_t& out);

  template <typename T>
  T decode(const std::span<uint8_t>& bytes);
};

template <typename T>
charter::schema::bytes_t encoder<scale_encoder_tag>::encode(const T& obj) {
  auto encoder = ::scale::encoder{};
  encoder << obj;
  return encoder.data();
}

template <typename T>
void encoder<scale_encoder_tag>::encode(const T& obj,
                                        charter::schema::bytes_t& out) {
  auto encoder = ::scale::encoder{out};
  encoder << obj;
}

template <>
template <typename T>
T encoder<scale_encoder_tag>::decode(const std::span<uint8_t>& bytes) {
  auto decoder = ::scale::decoder{bytes};
  T obj;
  decoder >> obj;
  return obj;
}

}  // namespace charter::charter::schema::encoding
#pragma once

#include <charter/schema/primitives.hpp>
#include <charter/schema/role_id.hpp>
#include <optional>

namespace charter::schema {

template <uint16_t Version>
struct upsert_role_assignment;

template <>
struct upsert_role_assignment<1> final {
  uint16_t version{1};
  policy_scope_t scope;
  signer_id_t subject;
  role_id_t role{role_id_t::initiator};
  bool enabled{true};
  std::optional<timestamp_milliseconds_t> not_before;
  std::optional<timestamp_milliseconds_t> expires_at;
  std::optional<bytes_t> note;
};

using upsert_role_assignment_t = upsert_role_assignment<1>;
using role_assignment_state_t = upsert_role_assignment<1>;

}  // namespace charter::schema

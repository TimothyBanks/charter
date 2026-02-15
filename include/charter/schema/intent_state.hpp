#pragma once

#include <charter/schema/primitives.hpp>

namespace charter::schema {

template <uint16_t Version>
struct intent_state;

template <>
struct intent_state<1> final {
  hash32_t workspace_id;
  hash32_t vault_id;
  hash32_t intent_id;
  signer_id_t created_by;
  timestamp_milliseconds_t create_at;
  timestamp_milliseconds_t not_before;
  std::optional<timestamp_milliseconds_t> expires_at;
};

using intent_state_t = intent_state<1>;

}  // namespace charter::schema
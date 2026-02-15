#pragma once

#include <charter/schema/primitives.hpp>

namespace charter::schema {

template <uint16_t Version> struct approval_state;

template <> struct approval_state<1> final {
  uint16_t version{1};
  hash32_t intent_id;
  signer_id_t signer;
  timestamp_milliseconds_t signed_at;
};

using approval_state_t = approval_state<1>;

} // namespace charter::schema
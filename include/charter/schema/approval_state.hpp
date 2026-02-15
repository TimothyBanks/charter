#pragma once

#include <charter/schema/primitives.hpp>
#include "primitives.hpp"

namespace charter::schema {

template <uint16_t Version>
struct approval_state;

template <>
struct approval_state<1> final {
  hash32_t intent_id;
  signer_id_t signer;
  timestamp_milliseconds_t signed_at;
};

}  // namespace charter::schema
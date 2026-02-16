#pragma once
#include <charter/schema/primitives.hpp>

namespace charter::schema {

template <uint16_t Version>
struct active_policy_pointer;

template <>
struct active_policy_pointer<1> final {
  uint16_t version{1};
  hash32_t policy_set_id;
  uint32_t policy_set_version;
};

using active_policy_pointer_t = active_policy_pointer<1>;

}  // namespace charter::schema
#pragma once

#include <charter/schema/primitives.hpp>

namespace charter::schema {

template <uint16_t Version>
struct approve_destination_update;

template <>
struct approve_destination_update<1> final {
  uint16_t version{1};
  hash32_t workspace_id;
  hash32_t destination_id;
  hash32_t update_id;
};

using approve_destination_update_t = approve_destination_update<1>;

}  // namespace charter::schema

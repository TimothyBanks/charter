#pragma once

#include <charter/schema/primitives.hpp>

#include <cstdint>

namespace charter::schema {

template <uint16_t Version>
struct jurisdiction;

template <>
struct jurisdiction<1> final {
  uint16_t version{1};
  hash32_t jurisdiction_id{};
};

using jurisdiction_t = jurisdiction<1>;

}  // namespace charter::schema

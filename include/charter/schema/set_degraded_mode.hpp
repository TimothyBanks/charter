#pragma once

#include <charter/schema/degraded_mode.hpp>
#include <charter/schema/primitives.hpp>
#include <optional>

namespace charter::schema {

template <uint16_t Version>
struct set_degraded_mode;

template <>
struct set_degraded_mode<1> final {
  uint16_t version{1};
  degraded_mode_t mode{degraded_mode_t::normal};
  std::optional<timestamp_milliseconds_t> effective_at;
  std::optional<bytes_t> reason;
};

using set_degraded_mode_t = set_degraded_mode<1>;
using degraded_mode_state_t = set_degraded_mode<1>;

}  // namespace charter::schema

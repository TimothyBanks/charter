#pragma once

#include <charter/schema/primitives.hpp>
#include <charter/schema/velocity_window.hpp>
#include <optional>

namespace charter::schema {

template <uint16_t Version>
struct velocity_counter_state;

template <>
struct velocity_counter_state<1> final {
  uint16_t version{1};
  hash32_t workspace_id;
  hash32_t vault_id;
  std::optional<asset_id_t> asset_id;
  velocity_window_t window{velocity_window_t::daily};
  timestamp_milliseconds_t window_start{};
  amount_t used_amount{};
  uint64_t tx_count{};
};

using velocity_counter_state_t = velocity_counter_state<1>;

}  // namespace charter::schema

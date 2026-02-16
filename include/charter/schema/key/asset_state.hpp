#pragma once
#include <charter/schema/asset_state.hpp>

namespace charter::schema::key {

template <typename Encoder>
charter::schema::bytes_t make_key(
    Encoder& encoder,
    const charter::schema::asset_state<1>& value) {
  thread_local auto output = charter::schema::bytes_t{};
  encoder.encode("ASSETSTATE|", output);
  encoder.encode(value.asset_id, output);
  return output;
}

}  // namespace charter::schema::key
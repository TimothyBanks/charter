#pragma once
#include <charter/schema/activate_policy_set.hpp>
#include <charter/schema/active_policy_pointer.hpp>

namespace charter::schema::key {

template <typename Encoder>
charter::schema::bytes_t make_key(
    Encoder& encoder,
    const charter::schema::activate_policy_set<1>& value) {
  auto output = charter::schema::bytes_t{};
  encoder.encode("ACTIVEPOLICYPTR|", output);
  encoder.encode(value.scope, output);
  encoder.encode("|", output);
  encoder.encode(value.policy_set_id, output);
  return output;
}

}  // namespace charter::schema::key
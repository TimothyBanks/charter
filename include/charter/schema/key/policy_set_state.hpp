#pragma once
#include <charter/schema/create_policy_set.hpp>

namespace charter::schema::key {

template <typename Encoder>
charter::schema::bytes_t make_key(
    Encoder& encoder,
    const charter::schema::create_policy_set<1>& value) {
  auto output = charter::schema::bytes_t{};
  encoder.encode("POLICYSET|", output);
  encoder.encode(value.scope, output);
  encoder.encode("|", output);
  encoder.encode(value.policy_set_id, output);
  encoder.encode("|", output);
  encoder.encode(value.policy_version, output);
  return output;
}

}  // namespace charter::schema::key
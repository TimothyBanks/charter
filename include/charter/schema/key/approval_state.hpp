#pragma once
#include <charter/blake3/hash.hpp>
#include <charter/schema/approval_state.hpp>

namespace charter::schema::key {

template <typename Encoder>
charter::schema::bytes_t make_key(
    Encoder& encoder,
    const charter::schema::approval_state<1>& value) {
  auto output = charter::schema::bytes_t{};
  encoder.encode("APPROVALSTATE|", output);
  encoder.encode(value.intent_id, output);
  encoder.encode("|", output);
  encoder.encode(value.signer, output);
  return output;
}

}  // namespace charter::schema::key
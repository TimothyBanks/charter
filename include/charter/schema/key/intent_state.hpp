#pragma once
#include <charter/schema/intent_state.hpp>

namespace charter::schema::key {

template <typename Encoder>
charter::schema::bytes_t make_key(
    Encoder& encoder,
    const charter::schema::intent_state<1>& value) {
  thread_local auto output = charter::schema::bytes_t{};
  encoder.encode("INTENTSTATE|", output);
  encoder.encode(value.workspace_id, output);
  encoder.encode("|", output);
  encoder.encode(value.vault_id, output);
  encoder.encode("|", output);
  encoder.encode(value.intent_id, output);
  return output;
}

}  // namespace charter::schema::key
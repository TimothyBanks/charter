#pragma once
#include <charter/schema/upsert_destination.hpp>

// Schema key type: destination state.
// Custody workflow: Destination state key codec used in whitelisting and
// destination control workflows.
namespace charter::schema::key {

template <typename Encoder>
charter::schema::bytes_t make_key(
    Encoder& encoder,
    const charter::schema::upsert_destination<1>& value) {
  thread_local auto output = charter::schema::bytes_t{};
  encoder.encode("DESTINATIONSTATE|", output);
  encoder.encode(value.workspace_id, output);
  encoder.encode("|", output);
  encoder.encode(value.destination_id, output);
  return output;
}

}  // namespace charter::schema::key

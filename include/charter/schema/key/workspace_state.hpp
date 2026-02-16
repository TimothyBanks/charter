#pragma once
#include <charter/schema/create_workspace.hpp>

namespace charter::schema::key {

template <typename Encoder>
charter::schema::bytes_t make_key(
    Encoder& encoder,
    const charter::schema::create_workspace<1>& value) {
  thread_local auto output = charter::schema::bytes_t{};
  encoder.encode("WORKSPACESTATE|", output);
  encoder.encode(value.workspace_id, output);
  return output;
}

}  // namespace charter::schema::key
#pragma once
#include <charter/schema/create_vault.hpp>

namespace charter::schema::key {

template <typename Encoder>
charter::schema::bytes_t make_key(
    Encoder& encoder,
    const charter::schema::create_vault<1>& value) {
  auto output = charter::schema::bytes_t{};
  encoder.encode("VAULTSTATE|", output);
  encoder.encode(value.workspace_id, output);
  encoder.encode("|", output);
  encoder.encode(value.vault_id, output);
  return output;
}

}  // namespace charter::schema::key
#pragma once
#include <charter/schema/primitives.hpp>

namespace charter::schema::key {

template <typename Encoder>
charter::schema::bytes_t make_key(Encoder& encoder, const signer_id_t& value) {
  auto output = charter::schema::bytes_t{};
  encoder.encode("NONCE|", output);
  encoder.encode(value, output);
  return output;
}

}  // namespace charter::schema::key
#pragma once
#include <charter/schema/primitives.hpp>

// Schema key type: nonce record.
// Custody workflow: Signer nonce keyspace used for anti-replay sequencing in
// transaction admission.
namespace charter::schema::key {

template <typename Encoder>
charter::schema::bytes_t make_key(Encoder& encoder, const signer_id_t& value) {
  thread_local auto output = charter::schema::bytes_t{};
  encoder.encode("NONCE|", output);
  encoder.encode(value, output);
  return output;
}

}  // namespace charter::schema::key

#pragma once
#include <charter/schema/attestation_record.hpp>

namespace charter::schema::key {

template <typename Encoder>
charter::schema::bytes_t make_key(
    Encoder& encoder,
    const charter::schema::attestation_record<1>& value) {
  thread_local auto output = charter::schema::bytes_t{};
  encoder.encode("ATTESTATIONRECORD|", output);
  encoder.encode(value.workspace_id, output);
  encoder.encode("|", output);
  encoder.encode(value.subject, output);
  encoder.encode("|", output);
  encoder.encode(value.claim, output);
  encoder.encode("|", output);
  encoder.encode(value.issuer, output);
  return output;
}

}  // namespace charter::schema::key
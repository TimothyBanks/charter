#pragma once
#include <charter/schema/upsert_attestation.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(upsert_attestation<1> &&o, ::scale::Encoder &encoder);
void decode(upsert_attestation<1> &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
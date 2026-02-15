#pragma once
#include <charter/schema/revoke_attestation.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(revoke_attestation<1> &&o, ::scale::Encoder &encoder);
void decode(revoke_attestation<1> &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
#pragma once
#include <charter/schema/attestation_status.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(attestation_status&& o, ::scale::Encoder& encoder);
void decode(attestation_status&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
#pragma once
#include <charter/schema/attestation_record.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::attestation_record<1> &&o, ::scale::Encoder &encoder);
void decode(charter::schema::attestation_record<1> &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
#pragma once
#include <charter/schema/claim_requirement.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(claim_requirement<1> &&o, ::scale::Encoder &encoder);
void decode(claim_requirement<1> &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
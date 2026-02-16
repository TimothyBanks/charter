#pragma once
#include <charter/schema/claim_requirement.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::claim_requirement<1> &&o,
            ::scale::Encoder &encoder);
void decode(charter::schema::claim_requirement<1> &&o,
            ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
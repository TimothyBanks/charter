#pragma once
#include <charter/schema/claim_type.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(claim_type_t&& o, ::scale::Encoder& encoder);
void decode(claim_type_t&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
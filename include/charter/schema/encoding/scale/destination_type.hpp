#pragma once
#include <charter/schema/destination_type.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(destination_type_t &&o, ::scale::Encoder &encoder);
void decode(destination_type_t &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
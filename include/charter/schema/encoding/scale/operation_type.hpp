#pragma once
#include <charter/schema/operation_type.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(operation_type_t&& o, ::scale::Encoder& encoder);
void decode(operation_type_t&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
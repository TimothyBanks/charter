#pragma once
#include <charter/schema/transfer_parameters.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::transfer_parameters<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::transfer_parameters<1>&& o,
            ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
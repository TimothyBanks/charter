#pragma once

#include <charter/schema/set_degraded_mode.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::set_degraded_mode<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::set_degraded_mode<1>&& o,
            ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale

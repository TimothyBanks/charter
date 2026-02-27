#pragma once

#include <charter/schema/approve_destination_update.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::approve_destination_update<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::approve_destination_update<1>&& o,
            ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale

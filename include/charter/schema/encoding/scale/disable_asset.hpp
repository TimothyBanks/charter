#pragma once
#include <charter/schema/disable_asset.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::disable_asset<1>&& o, ::scale::Encoder& encoder);
void decode(charter::schema::disable_asset<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
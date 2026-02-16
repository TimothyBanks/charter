#pragma once
#include <charter/schema/asset_state.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::asset_state<1>&& o, ::scale::Encoder& encoder);
void decode(charter::schema::asset_state<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
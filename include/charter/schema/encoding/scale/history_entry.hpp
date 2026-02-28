#pragma once

#include <charter/schema/history_entry.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::history_entry<1>&& o, ::scale::Encoder& encoder);
void decode(charter::schema::history_entry<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale

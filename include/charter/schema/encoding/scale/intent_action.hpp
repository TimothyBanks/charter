#pragma once
#include <charter/schema/intent_action.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(intent_action<1>&& o, ::scale::Encoder& encoder);
void decode(intent_action<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
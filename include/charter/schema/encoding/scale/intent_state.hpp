#pragma once
#include <charter/schema/intent_state.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(intent_state<1>&& o, ::scale::Encoder& encoder);
void decode(intent_state<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
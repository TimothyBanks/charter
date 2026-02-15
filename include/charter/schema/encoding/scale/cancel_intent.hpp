#pragma once
#include <charter/schema/cancel_intent.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(cancel_intent<1>&& o, ::scale::Encoder& encoder);
void decode(cancel_intent<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
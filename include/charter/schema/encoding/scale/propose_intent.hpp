#pragma once
#include <charter/schema/propose_intent.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(propose_intent<1>&& o, ::scale::Encoder& encoder);
void decode(propose_intent<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
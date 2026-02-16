#pragma once
#include <charter/schema/propose_intent.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::propose_intent<1> &&o, ::scale::Encoder &encoder);
void decode(charter::schema::propose_intent<1> &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
#pragma once
#include <charter/schema/approve_intent.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::approve_intent<1> &&o, ::scale::Encoder &encoder);
void decode(charter::schema::approve_intent<1> &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
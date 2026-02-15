#pragma once
#include <charter/schema/execute_intent.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(execute_intent<1> &&o, ::scale::Encoder &encoder);
void decode(execute_intent<1> &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
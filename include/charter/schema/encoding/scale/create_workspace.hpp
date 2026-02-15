#pragma once
#include <charter/schema/create_workspace.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(create_workspace<1> &&o, ::scale::Encoder &encoder);
void decode(create_workspace<1> &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
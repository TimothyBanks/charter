#pragma once
#include <charter/schema/create_workspace.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::create_workspace<1> &&o, ::scale::Encoder &encoder);
void decode(charter::schema::create_workspace<1> &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
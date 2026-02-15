#pragma once
#include <charter/schema/create_vault.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(create_vault<1> &&o, ::scale::Encoder &encoder);
void decode(create_vault<1> &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
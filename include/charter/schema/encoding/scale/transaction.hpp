#pragma once
#include <charter/schema/transaction.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::transaction<1> &&o, ::scale::Encoder &encoder);
void decode(charter::schema::transaction<1> &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
#pragma once
#include <charter/schema/upsert_destination.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(upsert_destination<1> &&o, ::scale::Encoder &encoder);
void decode(upsert_destination<1> &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
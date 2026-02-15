#pragma once
#include <charter/schema/intent_status.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(intent_status_t&& o, ::scale::Encoder& encoder);
void decode(intent_status_t&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
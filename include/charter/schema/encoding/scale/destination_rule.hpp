#pragma once
#include <charter/schema/destination_rule.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(destination_rule<1>&& o, ::scale::Encoder& encoder);
void decode(destination_rule<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
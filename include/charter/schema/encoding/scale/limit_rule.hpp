#pragma once
#include <charter/schema/limit_rule.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(limit_rule<1>&& o, ::scale::Encoder& encoder);
void decode(limit_rule<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
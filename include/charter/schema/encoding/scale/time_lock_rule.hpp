#pragma once
#include <charter/schema/time_lock_rule.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(time_lock_rule<1>&& o, ::scale::Encoder& encoder);
void decode(time_lock_rule<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
#pragma once

#include <charter/schema/velocity_limit_rule.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::velocity_limit_rule<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::velocity_limit_rule<1>&& o,
            ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale

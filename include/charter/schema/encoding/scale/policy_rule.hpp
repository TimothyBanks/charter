#pragma once
#include <charter/schema/policy_rule.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(policy_rule<1>&& o, ::scale::Encoder& encoder);
void decode(policy_rule<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
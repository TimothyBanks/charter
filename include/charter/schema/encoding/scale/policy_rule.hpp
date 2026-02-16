#pragma once
#include <charter/schema/policy_rule.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::policy_rule<1>&& o, ::scale::Encoder& encoder);
void decode(charter::schema::policy_rule<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
#pragma once
#include <charter/schema/activate_policy_set.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::activate_policy_set<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::activate_policy_set<1>&& o,
            ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
#pragma once
#include <charter/schema/active_policy_pointer.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::active_policy_pointer<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::active_policy_pointer<1>&& o,
            ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
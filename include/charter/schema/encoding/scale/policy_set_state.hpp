#pragma once
#include <charter/schema/policy_set_state.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(policy_set_state<1>&& o, ::scale::Encoder& encoder);
void decode(policy_set_state<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
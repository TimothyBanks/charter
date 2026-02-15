#pragma once
#include <charter/schema/activate_policy_set.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(activate_policy_set<1> &&o, ::scale::Encoder &encoder);
void decode(activate_policy_set<1> &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
#pragma once
#include <charter/schema/create_policy_set.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(create_policy_set<1> &&o, ::scale::Encoder &encoder);
void decode(create_policy_set<1> &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
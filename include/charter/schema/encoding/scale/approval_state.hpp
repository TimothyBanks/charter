#pragma once
#include <charter/schema/approval_state.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(approval_state<1> &&o, ::scale::Encoder &encoder);
void decode(approval_state<1> &&o, ::scale::Decoder &decoder);

} // namespace charter::schema::encoding::scale
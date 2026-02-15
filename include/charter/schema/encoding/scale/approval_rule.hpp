#pragma once
#include <charter/schema/approval_rule.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(approval_rule<1>&& o, ::scale::Encoder& encoder);
void decode(approval_rule<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
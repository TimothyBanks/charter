#pragma once
#include <charter/schema/chain.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(chain_type_t&& o, ::scale::Encoder& encoder);
void decode(chain_type_t&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
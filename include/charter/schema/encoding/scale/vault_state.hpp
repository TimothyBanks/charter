#pragma once
#include <charter/schema/vault_state.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(vault_state<1>&& o, ::scale::Encoder& encoder);
void decode(vault_state<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
#pragma once
#include <charter/schema/vault_model.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(vault_model_t&& o, ::scale::Encoder& encoder);
void decode(vault_model_t&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
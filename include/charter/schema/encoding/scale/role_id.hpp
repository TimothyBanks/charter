#pragma once
#include <charter/schema/role_id.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(role_id_t&& o, ::scale::Encoder& encoder);
void decode(role_id_t&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
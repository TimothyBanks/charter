#pragma once
#include <charter/schema/transfer_parameters.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(transfer_parameters<1>&& o, ::scale::Encoder& encoder);
void decode(transfer_parameters<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
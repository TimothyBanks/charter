#pragma once
#include <charter/schema/transaction.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(transaction<1>&& o, ::scale::Encoder& encoder);
void decode(transaction<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
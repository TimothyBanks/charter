#pragma once

#include <charter/schema/transaction_result.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::transaction_result<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::transaction_result<1>&& o,
            ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale

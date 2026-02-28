#pragma once

#include <charter/schema/transaction_event_attribute.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::transaction_event_attribute<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::transaction_event_attribute<1>&& o,
            ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale

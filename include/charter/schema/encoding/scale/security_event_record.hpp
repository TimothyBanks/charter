#pragma once

#include <charter/schema/security_event_record.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::security_event_record<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::security_event_record<1>&& o,
            ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale

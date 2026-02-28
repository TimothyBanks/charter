#pragma once

#include <charter/schema/snapshot_descriptor.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::snapshot_descriptor<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::snapshot_descriptor<1>&& o,
            ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale

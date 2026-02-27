#pragma once

#include <charter/schema/upsert_role_assignment.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::upsert_role_assignment<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::upsert_role_assignment<1>&& o,
            ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale

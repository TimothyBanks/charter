#pragma once
#include <charter/schema/revoke_attestation.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::revoke_attestation<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::revoke_attestation<1>&& o,
            ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
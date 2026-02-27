#pragma once

#include <charter/schema/upsert_signer_quarantine.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::upsert_signer_quarantine<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::upsert_signer_quarantine<1>&& o,
            ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale

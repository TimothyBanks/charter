#pragma once
#include <charter/schema/asset_ref.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::asset_ref_native_symbol<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::asset_ref_native_symbol<1>&& o,
            ::scale::Decoder& decoder);

void encode(charter::schema::asset_ref_contract_address<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::asset_ref_contract_address<1>&& o,
            ::scale::Decoder& decoder);

void encode(charter::schema::asset_ref_composite<1>&& o,
            ::scale::Encoder& encoder);
void decode(charter::schema::asset_ref_composite<1>&& o,
            ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
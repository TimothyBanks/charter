#pragma once
#include <charter/schema/primitives.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::encoding::scale {

void encode(public_key_t&& o, ::scale::Encoder& encoder);
void decode(public_key_t&& o, ::scale::Decoder& decoder);

void encode(signature_t&& o, ::scale::Encoder& encoder);
void decode(signature_t&& o, ::scale::Decoder& decoder);

void encode(vault_t&& o, ::scale::Encoder& encoder);
void decode(vault_t&& o, ::scale::Decoder& decoder);

void encode(policy_scope_t&& o, ::scale::Encoder& encoder);
void decode(policy_scope_t&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale
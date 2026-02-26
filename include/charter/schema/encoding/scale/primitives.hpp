#pragma once
#include <charter/schema/primitives.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::workspace_scope_t&& o, ::scale::Encoder& encoder);
void decode(charter::schema::workspace_scope_t&& o, ::scale::Decoder& decoder);

void encode(charter::schema::vault_t&& o, ::scale::Encoder& encoder);
void decode(charter::schema::vault_t&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale

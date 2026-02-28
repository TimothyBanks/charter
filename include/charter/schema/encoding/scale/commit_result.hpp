#pragma once

#include <charter/schema/commit_result.hpp>
#include <scale/scale.hpp>

namespace charter::schema::encoding::scale {

void encode(charter::schema::commit_result<1>&& o, ::scale::Encoder& encoder);
void decode(charter::schema::commit_result<1>&& o, ::scale::Decoder& decoder);

}  // namespace charter::schema::encoding::scale

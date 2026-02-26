#pragma once
#include <charter/schema/primitives.hpp>
#include <cstdint>
#include <span>
#include <string_view>

namespace charter::blake3 {

charter::schema::hash32_t hash(const std::string_view& str);
charter::schema::hash32_t hash(const charter::schema::bytes_view_t& bytes);

}  // namespace charter::blake3
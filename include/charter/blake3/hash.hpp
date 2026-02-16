#pragma once
#include <charter/schema/primitives.hpp>
#include <cstdint>
#include <span>
#include <string_view>

namespace charter::blake3 {

charter::schema::bytes_t hash(const std::string_view& str);
charter::schema::bytes_t hash(const std::span<const uint8_t>& bytes);

}  // namespace charter::blake3
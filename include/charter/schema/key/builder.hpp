#pragma once
#include <charter/schema/claim_type.hpp>
#include <charter/schema/primitives.hpp>
#include <cstdint>
#include <span>
#include <string_view>

namespace charter::schema::key {

struct builder final {
  charter::schema::bytes_t data;

  builder& write(const std::string_view& str);
  builder& write(const std::span<const uint8_t>& bytes);
  builder& write(const signer_id_t& signer_id);
  builder& write(const claim_type_t& claim_type);

  builder& hash(const std::string_view& str);
  builder& hash(const std::span<const uint8_t>& bytes);

  template <typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
  builder& write(T value) {
    for (size_t i = 0; i < sizeof(T); ++i) {
      data.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
    return *this;
  }
};

}  // namespace charter::schema::key
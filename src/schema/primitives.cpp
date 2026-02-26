#include <charter/common/critical.hpp>
#include <charter/schema/primitives.hpp>

#include <algorithm>
#include <iterator>
#include <string_view>

namespace charter::schema {

namespace {

uint8_t hex_nibble(const char c) {
  const auto uc = static_cast<unsigned char>(c);
  if (uc >= static_cast<unsigned char>('0') &&
      uc <= static_cast<unsigned char>('9')) {
    return static_cast<uint8_t>(uc - static_cast<unsigned char>('0'));
  }
  if (uc >= static_cast<unsigned char>('a') &&
      uc <= static_cast<unsigned char>('f')) {
    return static_cast<uint8_t>(uc - static_cast<unsigned char>('a') + 10);
  }
  if (uc >= static_cast<unsigned char>('A') &&
      uc <= static_cast<unsigned char>('F')) {
    return static_cast<uint8_t>(uc - static_cast<unsigned char>('A') + 10);
  }
  charter::common::critical("make_hash32 expected a hexadecimal string");
}

std::string_view normalize_hex_input(std::string_view input) {
  if (input.size() >= 2 && input[0] == '0' &&
      (input[1] == 'x' || input[1] == 'X')) {
    input.remove_prefix(2);
  }
  return input;
}

hash32_t decode_hex_hash32(std::string_view hex) {
  auto normalized = normalize_hex_input(hex);
  if (normalized.size() != 64) {
    charter::common::critical("make_hash32 expected 64 hex characters");
  }

  auto hash = hash32_t{};
  for (std::size_t i = 0; i < hash.size(); ++i) {
    const auto high = hex_nibble(normalized[2 * i]);
    const auto low = hex_nibble(normalized[(2 * i) + 1]);
    hash[i] = static_cast<uint8_t>((high << 4u) | low);
  }
  return hash;
}

}  // namespace

bytes_t make_bytes(const bytes_view_t& bytes) {
  return bytes_t{std::begin(bytes), std::end(bytes)};
}

bytes_t make_bytes(const std::string& bytes) {
  return bytes_t{std::begin(bytes), std::end(bytes)};
}

bytes_t make_bytes(const std::string_view& bytes) {
  return bytes_t{std::begin(bytes), std::end(bytes)};
}

bytes_view_t make_bytes_view(const bytes_t& bytes) {
  return bytes_view_t{bytes};
}

bytes_view_t make_bytes_view(const std::string& bytes) {
  return bytes_view_t{reinterpret_cast<const uint8_t*>(bytes.c_str()),
                      bytes.size()};
}

bytes_view_t make_bytes_view(const std::string_view& bytes) {
  return bytes_view_t{reinterpret_cast<const uint8_t*>(bytes.data()),
                      bytes.size()};
}

std::string_view make_string_view(const bytes_t& bytes) {
  return std::string_view{reinterpret_cast<const char*>(bytes.data()),
                          bytes.size()};
}

std::string_view make_string_view(const bytes_view_t& bytes) {
  return std::string_view{reinterpret_cast<const char*>(bytes.data()),
                          bytes.size()};
}

std::string make_string(const bytes_t& bytes) {
  return std::string{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

std::string make_string(const bytes_view_t& bytes) {
  return std::string{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

hash32_t make_hash32(const bytes_t& bytes) {
  if (bytes.size() != 32) {
    charter::common::critical("make_hash32 expected exactly 32 bytes");
  }
  auto hash = hash32_t{};
  std::copy(std::begin(bytes), std::end(bytes), std::begin(hash));
  return hash;
}

hash32_t make_hash32(const std::string& bytes) {
  return decode_hex_hash32(bytes);
}

hash32_t make_hash32(const std::string_view& bytes) {
  return decode_hex_hash32(bytes);
}

hash32_t make_zero_hash() {
  return {};
}

}  // namespace charter::schema

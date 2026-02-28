#include <charter/common/critical.hpp>
#include <charter/schema/primitives.hpp>

#include <algorithm>
#include <iterator>
#include <string_view>

namespace charter::schema {

namespace {

std::optional<charter::schema::hash32_t> try_make_hash32_internal(
    std::string_view hex) {
  if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
    hex.remove_prefix(2);
  }

  if (hex.size() == 32) {
    auto hash = charter::schema::hash32_t{};
    std::copy_n(std::begin(hex), hash.size(), std::begin(hash));
    return hash;
  }

  if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
    hex.remove_prefix(2);
  }

  if (hex.size() != 64) {
    return std::nullopt;
  }

  auto nibble = [](char c) -> std::optional<uint8_t> {
    if (c >= '0' && c <= '9') {
      return static_cast<uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
      return static_cast<uint8_t>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
      return static_cast<uint8_t>(c - 'A' + 10);
    }
    return std::nullopt;
  };

  auto hash = charter::schema::hash32_t{};
  for (size_t i = 0; i < hash.size(); ++i) {
    auto hi = nibble(hex[2 * i]);
    auto lo = nibble(hex[(2 * i) + 1]);
    if (!hi || !lo) {
      return std::nullopt;
    }
    hash[i] = static_cast<uint8_t>((*hi << 4u) | *lo);
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
  auto hash = try_make_hash32_internal(bytes);
  return *hash;
}

hash32_t make_hash32(const std::string_view& bytes) {
  auto hash = try_make_hash32_internal(bytes);
  return *hash;
}

std::optional<hash32_t> try_make_hash32(const std::string& bytes) {
  return try_make_hash32_internal(bytes);
}

std::optional<hash32_t> try_make_hash32(const std::string_view& bytes) {
  return try_make_hash32_internal(bytes);
}

hash32_t make_zero_hash() {
  return {};
}

}  // namespace charter::schema

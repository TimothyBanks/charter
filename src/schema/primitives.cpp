#include <charter/common/critical.hpp>
#include <charter/schema/primitives.hpp>

#include <algorithm>
#include <cctype>
#include <iterator>
#include <string_view>

namespace charter::schema {

namespace {

std::string_view normalize_hex(std::string_view input) {
  if (input.size() >= 2 && input[0] == '0' &&
      (input[1] == 'x' || input[1] == 'X')) {
    input.remove_prefix(2);
  }
  return input;
}

std::optional<uint8_t> hex_nibble(const char c) {
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
}

std::optional<charter::schema::bytes_t> try_from_hex_internal(
    std::string_view hex) {
  hex = normalize_hex(hex);
  if ((hex.size() % 2) != 0) {
    return std::nullopt;
  }

  auto decoded = charter::schema::bytes_t{};
  decoded.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    auto high = hex_nibble(hex[i]);
    auto low = hex_nibble(hex[i + 1]);
    if (!high || !low) {
      return std::nullopt;
    }
    decoded.push_back(static_cast<uint8_t>((*high << 4u) | *low));
  }
  return decoded;
}

std::optional<charter::schema::hash32_t> try_make_hash32_internal(
    std::string_view hex) {
  hex = normalize_hex(hex);

  if (hex.size() == 32) {
    auto hash = charter::schema::hash32_t{};
    std::copy_n(std::begin(hex), hash.size(), std::begin(hash));
    return hash;
  }

  auto decoded = try_from_hex_internal(hex);
  if (!decoded || decoded->size() != 32) {
    return std::nullopt;
  }

  auto hash = charter::schema::hash32_t{};
  std::copy(decoded->begin(), decoded->end(), hash.begin());
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

std::string to_hex(const charter::schema::bytes_view_t& bytes) {
  static constexpr auto kHex = std::string_view{"0123456789abcdef"};
  auto out = std::string{};
  out.resize(bytes.size() * 2);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    out[(2 * i)] = kHex[(bytes[i] >> 4u) & 0x0Fu];
    out[(2 * i) + 1] = kHex[bytes[i] & 0x0Fu];
  }
  return out;
}

std::optional<bytes_t> try_from_hex(const std::string_view hex) {
  return try_from_hex_internal(hex);
}

bytes_t from_hex(const std::string_view hex) {
  auto decoded = try_from_hex_internal(hex);
  if (!decoded.has_value()) {
    charter::common::critical("invalid hex input");
  }
  return *decoded;
}

std::string to_base64(const charter::schema::bytes_view_t& bytes) {
  static constexpr auto kTable =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  auto out = std::string{};
  out.reserve(((bytes.size() + 2) / 3) * 4);

  auto index = size_t{0};
  while ((index + 3) <= bytes.size()) {
    auto value = (static_cast<uint32_t>(bytes[index]) << 16u) |
                 (static_cast<uint32_t>(bytes[index + 1]) << 8u) |
                 static_cast<uint32_t>(bytes[index + 2]);
    out.push_back(kTable[(value >> 18u) & 0x3Fu]);
    out.push_back(kTable[(value >> 12u) & 0x3Fu]);
    out.push_back(kTable[(value >> 6u) & 0x3Fu]);
    out.push_back(kTable[value & 0x3Fu]);
    index += 3;
  }

  if (index < bytes.size()) {
    auto value = static_cast<uint32_t>(bytes[index]) << 16u;
    out.push_back(kTable[(value >> 18u) & 0x3Fu]);
    if ((index + 1) < bytes.size()) {
      value |= static_cast<uint32_t>(bytes[index + 1]) << 8u;
      out.push_back(kTable[(value >> 12u) & 0x3Fu]);
      out.push_back(kTable[(value >> 6u) & 0x3Fu]);
      out.push_back('=');
    } else {
      out.push_back(kTable[(value >> 12u) & 0x3Fu]);
      out.push_back('=');
      out.push_back('=');
    }
  }

  return out;
}

std::string to_base64(const charter::schema::bytes_t& bytes) {
  return to_base64(charter::schema::bytes_view_t{bytes.data(), bytes.size()});
}

std::optional<bytes_t> try_from_base64(const std::string_view encoded) {
  auto compact = std::string{};
  compact.reserve(encoded.size());
  for (const auto ch : encoded) {
    if (std::isspace(static_cast<unsigned char>(ch)) != 0) {
      continue;
    }
    compact.push_back(ch);
  }

  if ((compact.size() % 4) != 0) {
    return std::nullopt;
  }

  auto decode_char = [](const char ch) -> std::optional<uint8_t> {
    if (ch >= 'A' && ch <= 'Z') {
      return static_cast<uint8_t>(ch - 'A');
    }
    if (ch >= 'a' && ch <= 'z') {
      return static_cast<uint8_t>(ch - 'a' + 26);
    }
    if (ch >= '0' && ch <= '9') {
      return static_cast<uint8_t>(ch - '0' + 52);
    }
    if (ch == '+') {
      return uint8_t{62};
    }
    if (ch == '/') {
      return uint8_t{63};
    }
    return std::nullopt;
  };

  auto out = bytes_t{};
  out.reserve((compact.size() / 4) * 3);

  for (size_t i = 0; i < compact.size(); i += 4) {
    auto c0 = compact[i];
    auto c1 = compact[i + 1];
    auto c2 = compact[i + 2];
    auto c3 = compact[i + 3];

    auto v0 = decode_char(c0);
    auto v1 = decode_char(c1);
    if (!v0 || !v1) {
      return std::nullopt;
    }

    auto is_last_chunk = (i + 4) == compact.size();
    if (c2 == '=') {
      if (c3 != '=' || !is_last_chunk) {
        return std::nullopt;
      }
      auto value = (static_cast<uint32_t>(*v0) << 18u) |
                   (static_cast<uint32_t>(*v1) << 12u);
      out.push_back(static_cast<uint8_t>((value >> 16u) & 0xFFu));
      continue;
    }

    auto v2 = decode_char(c2);
    if (!v2) {
      return std::nullopt;
    }
    if (c3 == '=') {
      if (!is_last_chunk) {
        return std::nullopt;
      }
      auto value = (static_cast<uint32_t>(*v0) << 18u) |
                   (static_cast<uint32_t>(*v1) << 12u) |
                   (static_cast<uint32_t>(*v2) << 6u);
      out.push_back(static_cast<uint8_t>((value >> 16u) & 0xFFu));
      out.push_back(static_cast<uint8_t>((value >> 8u) & 0xFFu));
      continue;
    }

    auto v3 = decode_char(c3);
    if (!v3) {
      return std::nullopt;
    }
    auto value = (static_cast<uint32_t>(*v0) << 18u) |
                 (static_cast<uint32_t>(*v1) << 12u) |
                 (static_cast<uint32_t>(*v2) << 6u) |
                 static_cast<uint32_t>(*v3);
    out.push_back(static_cast<uint8_t>((value >> 16u) & 0xFFu));
    out.push_back(static_cast<uint8_t>((value >> 8u) & 0xFFu));
    out.push_back(static_cast<uint8_t>(value & 0xFFu));
  }

  return out;
}

bytes_t from_base64(const std::string_view encoded) {
  auto decoded = try_from_base64(encoded);
  if (!decoded.has_value()) {
    charter::common::critical("invalid base64 input");
  }
  return *decoded;
}

hash32_t make_zero_hash() {
  return {};
}

}  // namespace charter::schema

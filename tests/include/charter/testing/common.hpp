#pragma once

#include <charter/schema/primitives.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>

namespace charter::testing {

inline charter::schema::hash32_t make_hash(const uint8_t seed) {
  auto out = charter::schema::hash32_t{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(seed + static_cast<uint8_t>(i));
  }
  return out;
}

inline charter::schema::named_signer_t make_named_signer_id(
    const uint8_t seed) {
  auto named = charter::schema::named_signer_t{};
  named[0] = seed;
  return named;
}

inline charter::schema::signer_id_t make_named_signer(const uint8_t seed) {
  return charter::schema::signer_id_t{make_named_signer_id(seed)};
}

inline charter::schema::ed25519_signer_id make_ed25519_signer(
    const uint8_t seed) {
  auto signer = charter::schema::ed25519_signer_id{};
  for (std::size_t i = 0; i < signer.public_key.size(); ++i) {
    signer.public_key[i] = static_cast<uint8_t>(seed + static_cast<uint8_t>(i));
  }
  return signer;
}

inline std::string make_db_path(const std::string_view prefix) {
  const auto now =
      std::chrono::high_resolution_clock::now().time_since_epoch().count();
  const auto path = std::filesystem::temp_directory_path() /
                    (std::string{prefix} + "_" +
                     std::to_string(static_cast<unsigned long long>(now)));
  return path.string();
}

inline void remove_path(const std::string& path) {
  auto error = std::error_code{};
  std::filesystem::remove_all(path, error);
}

}  // namespace charter::testing

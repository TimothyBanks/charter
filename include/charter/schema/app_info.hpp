#pragma once

#include <charter/schema/primitives.hpp>
#include <cstdint>
#include <string>

namespace charter::schema {

template <uint16_t Version>
struct app_info;

template <>
struct app_info<1> final {
  uint16_t schema_version{1};
  std::string data{"charter-custody"};
  std::string version{"0.1.0-poc"};
  uint64_t app_version{1};
  int64_t last_block_height{};
  hash32_t last_block_state_root;
};

using app_info_t = app_info<1>;

}  // namespace charter::schema

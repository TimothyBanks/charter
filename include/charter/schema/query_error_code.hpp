#pragma once

#include <cstdint>

namespace charter::schema {

enum class query_error_code : uint32_t {
  invalid_key = 1,
  not_found = 2,
  unsupported_path = 3,
};

}  // namespace charter::schema

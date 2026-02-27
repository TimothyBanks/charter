#pragma once

#include <cstdint>

namespace charter::schema {

enum class degraded_mode_t : uint8_t {
  normal = 0,
  read_only = 1,
  emergency_halt = 2,
};

}  // namespace charter::schema

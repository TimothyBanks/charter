#pragma once

#include <cstdint>

namespace charter::schema {

enum class velocity_window_t : uint8_t {
  daily = 0,
  weekly = 1,
  monthly = 2,
};

}  // namespace charter::schema

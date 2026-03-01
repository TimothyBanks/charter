#pragma once

#include <cstdint>

// Schema type: velocity window.
// Custody workflow: Velocity bucket enum: daily/weekly/monthly windows for
// cumulative transfer controls.
namespace charter::schema {

enum class velocity_window_t : uint8_t {
  daily = 0,
  weekly = 1,
  monthly = 2,
};

}  // namespace charter::schema

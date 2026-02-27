#pragma once

#include <cstdint>

namespace charter::schema {

enum class security_event_severity_t : uint8_t {
  info = 0,
  warning = 1,
  error = 2,
  critical = 3,
};

}  // namespace charter::schema

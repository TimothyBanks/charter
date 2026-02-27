#pragma once

#include <cstdint>

namespace charter::schema {

enum class destination_update_status_t : uint8_t {
  pending_approval = 0,
  executable = 1,
  applied = 2,
  cancelled = 3,
};

}  // namespace charter::schema

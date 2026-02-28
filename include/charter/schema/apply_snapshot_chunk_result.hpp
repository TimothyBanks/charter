#pragma once

#include <cstdint>

namespace charter::schema {

enum class apply_snapshot_chunk_result : uint8_t {
  unknown = 0,
  accept = 1,
  abort = 2,
  retry = 3,
  retry_snapshot = 4,
  reject_snapshot = 5,
};

}  // namespace charter::schema

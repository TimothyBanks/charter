#pragma once

#include <cstdint>

namespace charter::schema {

enum class offer_snapshot_result : uint8_t {
  unknown = 0,
  accept = 1,
  abort = 2,
  reject = 3,
  reject_format = 4,
  reject_sender = 5,
};

}  // namespace charter::schema

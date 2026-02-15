#pragma once

namespace charter::schema {

enum class intent_status_t : uint8_t {
  proposed = 0,
  pending_approval = 1,
  executable = 2,
  executed = 3,
  cancelled = 4,
  expired = 5
};

}
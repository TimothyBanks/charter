#pragma once

#include <cstdint>

// Schema type: destination update status.
// Custody workflow: Destination update lifecycle enum: state machine for
// proposed/approved/applied updates.
namespace charter::schema {

enum class destination_update_status_t : uint8_t {
  pending_approval = 0,
  executable = 1,
  applied = 2,
  cancelled = 3,
};

}  // namespace charter::schema

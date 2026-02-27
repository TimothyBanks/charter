#pragma once

#include <cstdint>

namespace charter::schema {

enum class security_event_type_t : uint16_t {
  tx_validation_failed = 1,
  tx_execution_denied = 2,
  authz_denied = 3,
  policy_denied = 4,
  replay_checkpoint_mismatch = 5,
  snapshot_rejected = 6,
  snapshot_applied = 7,
  backup_import_failed = 8,
  role_assignment_updated = 9,
  signer_quarantine_updated = 10,
  degraded_mode_updated = 11,
};

}  // namespace charter::schema

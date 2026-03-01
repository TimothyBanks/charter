#pragma once

#include <cstdint>

// Schema type: security event severity.
// Custody workflow: Security criticality scale: standardizes event severity for
// escalation workflows.
namespace charter::schema {

enum class security_event_severity_t : uint8_t {
  info = 0,
  warning = 1,
  error = 2,
  critical = 3,
};

}  // namespace charter::schema

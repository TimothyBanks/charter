#pragma once
#include <cstdint>

// Schema type: operation type.
// Custody workflow: Policy operation classifier: maps actions (for now
// transfer) to rule selection in policy sets.
namespace charter::schema {

enum class operation_type_t : uint8_t {
  transfer = 0,
  contract_call = 1,
  raw_sign = 2
};

}

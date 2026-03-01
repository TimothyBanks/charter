#pragma once
#include <cstdint>

// Schema type: attestation status.
// Custody workflow: Attestation lifecycle enum: active vs revoked compliance
// evidence state.
namespace charter::schema {

enum class attestation_status_t : uint8_t { active = 0, revoked = 1 };

}

#pragma once

#include <charter/schema/attestation_status.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(charter::schema,
                             attestation_status_t,
                             attestation_status_t::active,
                             attestation_status_t::revoked)
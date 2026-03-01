#pragma once

#include <charter/schema/settlement_authority_mode.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(
    charter::schema,
    settlement_authority_mode_t,
    charter::schema::settlement_authority_mode_t::custodian_signed,
    charter::schema::settlement_authority_mode_t::client_signed)

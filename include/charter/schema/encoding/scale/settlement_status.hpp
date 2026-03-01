#pragma once

#include <charter/schema/settlement_status.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(charter::schema,
                             settlement_status_t,
                             charter::schema::settlement_status_t::none,
                             charter::schema::settlement_status_t::authorized,
                             charter::schema::settlement_status_t::submitted,
                             charter::schema::settlement_status_t::confirmed,
                             charter::schema::settlement_status_t::failed,
                             charter::schema::settlement_status_t::expired)

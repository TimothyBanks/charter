#pragma once

#include <charter/schema/degraded_mode.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(charter::schema,
                             degraded_mode_t,
                             charter::schema::degraded_mode_t::normal,
                             charter::schema::degraded_mode_t::read_only,
                             charter::schema::degraded_mode_t::emergency_halt)

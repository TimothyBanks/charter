#pragma once

#include <charter/schema/destination_update_status.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(
    charter::schema,
    destination_update_status_t,
    charter::schema::destination_update_status_t::pending_approval,
    charter::schema::destination_update_status_t::executable,
    charter::schema::destination_update_status_t::applied,
    charter::schema::destination_update_status_t::cancelled)

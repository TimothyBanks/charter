#pragma once

#include <charter/schema/security_event_severity.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(
    charter::schema,
    security_event_severity_t,
    charter::schema::security_event_severity_t::info,
    charter::schema::security_event_severity_t::warning,
    charter::schema::security_event_severity_t::error,
    charter::schema::security_event_severity_t::critical)

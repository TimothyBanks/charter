#pragma once

#include <charter/schema/intent_status.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(charter::schema,
                             intent_status_t,
                             charter::schema::intent_status_t::proposed,
                             charter::schema::intent_status_t::approved,
                             charter::schema::intent_status_t::executed,
                             charter::schema::intent_status_t::cancelled,
                             charter::schema::intent_status_t::expired)
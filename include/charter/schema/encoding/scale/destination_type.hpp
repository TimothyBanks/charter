#pragma once

#include <charter/schema/destination_type.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(charter::schema,
                             destination_type_t,
                             charter::schema::destination_type_t::address,
                             charter::schema::destination_type_t::contract)
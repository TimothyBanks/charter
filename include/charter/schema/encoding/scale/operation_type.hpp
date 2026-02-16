#pragma once

#include <charter/schema/operation_type.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(charter::schema,
                             operation_type_t,
                             charter::schema::operation_type_t::transfer,
                             charter::schema::operation_type_t::contract_call,
                             charter::schema::operation_type_t::raw_sign)
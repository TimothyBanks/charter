#pragma once

#include <charter/schema/velocity_window.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(charter::schema,
                             velocity_window_t,
                             charter::schema::velocity_window_t::daily,
                             charter::schema::velocity_window_t::weekly,
                             charter::schema::velocity_window_t::monthly)

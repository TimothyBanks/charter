#pragma once

#include <charter/schema/asset_kind.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(charter::schema,
                             asset_kind_t,
                             charter::schema::asset_kind_t::native,
                             charter::schema::asset_kind_t::erc20,
                             charter::schema::asset_kind_t::erc721,
                             charter::schema::asset_kind_t::erc1115,
                             charter::schema::asset_kind_t::other)
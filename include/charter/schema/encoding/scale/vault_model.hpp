#pragma once

#include <charter/schema/vault_model.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(charter::schema, vault_model_t,
                             charter::schema::vault_model_t::segregated,
                             charter::schema::vault_model_t::omnibus)
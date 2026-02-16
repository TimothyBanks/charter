#pragma once 

#include <charter/schema/role_id.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(charter::schema, role_id_t,
  charter::schema::role_id_t::initiator,
  charter::schema::role_id_t::approver,
  charter::schema::role_id_t::executor,
  charter::schema::role_id_t::admin,
  charter::schema::role_id_t::auditor,
  charter::schema::role_id_t::guardian,
  charter::schema::role_id_t::attestor
)
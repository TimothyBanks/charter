#pragma once 

#include <charter/schema/claim_type.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(charter::schema, claim_type,
  charter::schema::claim_type::kyb_verified,
  charter::schema::claim_type::sanctions_cleared,
  charter::schema::claim_type::travel_rule_ok,
  charter::schema::claim_type::risk_approved
)
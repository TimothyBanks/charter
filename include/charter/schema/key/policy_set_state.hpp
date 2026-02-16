#pragma once
#include <charter/schema/create_policy_set.hpp>

namespace charter::schema::key {

charter::schema::bytes_t make_key(
    const charter::schema::create_policy_set<1>& value);
}
#pragma once
#include <charter/schema/active_policy_pointer.hpp>

namespace charter::schema::key {

charter::schema::bytes_t make_key(
    const charter::schema::active_policy_pointer<1>& value);

}
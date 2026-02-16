#pragma once
#include <charter/schema/create_workspace.hpp>

namespace charter::schema::key {

charter::schema::bytes_t make_key(
    const charter::schema::create_workspace<1>& value);
}
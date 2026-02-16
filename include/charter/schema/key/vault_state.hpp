#pragma once
#include <charter/schema/create_vault.hpp>

namespace charter::schema::key {

charter::schema::bytes_t make_key(
    const charter::schema::create_vault<1>& value);
}
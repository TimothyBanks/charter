#pragma once
#include <charter/schema/approval_state.hpp>

namespace charter::schema::key {

charter::schema::bytes_t make_key(
    const charter::schema::approval_state<1>& value);

}
#pragma once
#include <charter/schema/primitives.hpp>

namespace charter::schema::key {

charter::schema::bytes_t make_key(const signer_id_t& value);

}
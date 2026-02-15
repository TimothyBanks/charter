#pragma once
#include <charter/schema/create_vault.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const create_vault<1> &o);

} // namespace charter::schema::key::rocksdb
#pragma once
#include <charter/schema/role_id.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const role_id_t &o);

} // namespace charter::schema::key::rocksdb
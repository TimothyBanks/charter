#pragma once
#include <charter/schema/destination_type.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const destination_type_t &o);

} // namespace charter::schema::key::rocksdb
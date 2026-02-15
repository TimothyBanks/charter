#pragma once
#include <charter/schema/upsert_destination.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const upsert_destination<1>& o);

}  // namespace charter::schema::key::rocksdb
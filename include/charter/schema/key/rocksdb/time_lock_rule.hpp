#pragma once
#include <charter/schema/time_lock_rule.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const time_lock_rule<1>& o);

}  // namespace charter::schema::key::rocksdb